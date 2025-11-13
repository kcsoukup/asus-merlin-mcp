"""
URL and Keyword filtering tool handlers for ASUS Merlin MCP server.

This module provides tools for managing URL/keyword filtering including:
- Global URL filtering (blacklist/whitelist mode)
- Keyword filtering (block URLs containing keywords)
- Per-device URL filtering (assign different filters to specific MAC addresses)
"""

from typing import Any

from mcp.types import TextContent

from config.constants import (
    KEYWORD_FILTER_MAX_RULES,
    NVRAM_KEYWORD_ENABLE,
    NVRAM_KEYWORD_RULELIST,
    NVRAM_KEYWORD_SCHED,
    NVRAM_URL_ENABLE,
    NVRAM_URL_MODE,
    NVRAM_URL_RULELIST,
    NVRAM_URL_SCHED,
    URL_FILTER_MAX_RULES,
    URL_MODE_BLACKLIST,
    URL_MODE_WHITELIST,
)
from core.ssh_client import RouterSSHClient


def parse_url_filter_rules(rulelist_value: str) -> list[str]:
    """
    Parse URL filter rulelist into list of patterns.

    Format: <1>ALL>pattern1>1>ALL>pattern2>
    Each rule is: 1>ALL>pattern
    Multiple rules separated by starting with '<'

    Args:
        rulelist_value: NVRAM url_rulelist value

    Returns:
        List of URL patterns (just the pattern part, not full rule)
    """
    if not rulelist_value or rulelist_value.strip() == "":
        return []

    patterns = []
    # Split by '<' to get individual rules (filter out empty strings)
    rule_blocks = [block for block in rulelist_value.split("<") if block.strip()]

    for block in rule_blocks:
        # Each block is like: "1>ALL>pattern>" or "1>ALL>pattern>1>ALL>pattern2>"
        # We need to handle the case where blocks are concatenated without '<'
        # Split by '>' and take every 3rd element starting from index 2
        parts = block.rstrip(">").split(">")

        # Process in groups of 3: [enabled, scope, pattern]
        for i in range(0, len(parts), 3):
            if i + 2 < len(parts):
                pattern = parts[i + 2].strip()
                if pattern:
                    patterns.append(pattern)

    return patterns


def build_url_filter_rules(patterns: list[str]) -> str:
    """
    Build URL filter rulelist from list of patterns.

    Args:
        patterns: List of URL patterns

    Returns:
        NVRAM-formatted url_rulelist string
    """
    if not patterns:
        return ""

    # Each pattern becomes: 1>ALL>pattern
    rules = [f"<1>ALL>{pattern}" for pattern in patterns]
    return "".join(rules) + ">"


def parse_keyword_list(keyword_value: str) -> list[str]:
    """
    Parse keyword filter list from NVRAM format.

    Keyword format: <keyword1<keyword2<keyword3
    Uses '<' as delimiter between keywords

    Args:
        keyword_value: NVRAM keyword_rulelist value

    Returns:
        List of keywords
    """
    if not keyword_value or keyword_value.strip() == "":
        return []

    # Split by '<' and filter empty strings
    keywords = [k.strip() for k in keyword_value.split("<") if k.strip()]
    return keywords


def build_keyword_list(keywords: list[str]) -> str:
    """
    Build keyword filter rulelist from list of keywords.

    Keyword format: <keyword1<keyword2<keyword3
    Uses '<' as delimiter between keywords (NOT '>')

    Args:
        keywords: List of keywords

    Returns:
        NVRAM-formatted keyword_rulelist string
    """
    if not keywords:
        return ""

    # Build: <keyword1<keyword2<keyword3
    return "<" + "<".join(keywords)


def handle_get_url_filter_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    Get global URL filter status and configuration.

    Shows:
    - Enabled/disabled status
    - Filter mode (blacklist vs whitelist)
    - Number of URL rules configured
    - Schedule status

    Args:
        router: RouterSSHClient instance
        _arguments: Not used

    Returns:
        list[TextContent]: Formatted status information
    """
    # Get URL filter settings
    enable_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_ENABLE}")
    mode_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_MODE}")
    rulelist_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_RULELIST}")
    sched_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_SCHED}")

    enabled = enable_output.strip() == "1"
    mode = mode_output.strip()
    mode_str = (
        "Whitelist (allow only)"
        if mode == URL_MODE_WHITELIST
        else "Blacklist (block listed)"
    )

    patterns = parse_url_filter_rules(rulelist_output.strip())
    rule_count = len(patterns)

    result = "🌐 URL FILTER STATUS\n\n"
    result += f"Status: {'✓ ENABLED' if enabled else '✗ DISABLED'}\n"
    result += f"Filter Mode: {mode_str}\n"
    result += f"URL Rules: {rule_count}/{URL_FILTER_MAX_RULES}\n"
    result += f"Schedule: {sched_output.strip() or 'Always active'}\n"

    if patterns:
        result += "\n📋 CONFIGURED URL RULES:\n"
        for i, pattern in enumerate(patterns, 1):
            result += f"  {i}. {pattern}\n"

    return [TextContent(type="text", text=result)]


def handle_add_url_filter(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """
    Add URL pattern to global filter list.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with 'url_pattern' key

    Returns:
        list[TextContent]: Success or error message
    """
    url_pattern = arguments.get("url_pattern", "").strip()

    if not url_pattern:
        return [TextContent(type="text", text="Error: URL pattern is required")]

    # Get current rulelist
    rulelist_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_RULELIST}")
    current_patterns = parse_url_filter_rules(rulelist_output.strip())

    # Check limit
    if len(current_patterns) >= URL_FILTER_MAX_RULES:
        return [
            TextContent(
                type="text",
                text=f"Error: Maximum {URL_FILTER_MAX_RULES} URL filter rules already configured",
            )
        ]

    # Check for duplicates
    if url_pattern.lower() in [p.lower() for p in current_patterns]:
        return [
            TextContent(
                type="text",
                text=f"Error: URL pattern '{url_pattern}' already exists in filter list",
            )
        ]

    # Add new pattern
    current_patterns.append(url_pattern)

    # Build new rulelist
    new_rulelist = build_url_filter_rules(current_patterns)

    # Set new rulelist and enable URL filtering
    router.execute_command(f'nvram set {NVRAM_URL_RULELIST}="{new_rulelist}"')
    router.execute_command(f"nvram set {NVRAM_URL_ENABLE}=1")
    router.execute_command("nvram commit")

    # Restart firewall to apply changes
    router.execute_command("service restart_firewall")

    result = "✓ URL Filter Added\n\n"
    result += f"Pattern: {url_pattern}\n"
    result += f"Total rules: {len(current_patterns)}/{URL_FILTER_MAX_RULES}\n"
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


def handle_remove_url_filter(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Remove URL pattern from global filter list.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with 'url_pattern' key

    Returns:
        list[TextContent]: Success or error message
    """
    url_pattern = arguments.get("url_pattern", "").strip()

    if not url_pattern:
        return [TextContent(type="text", text="Error: URL pattern is required")]

    # Get current rulelist
    rulelist_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_RULELIST}")
    current_patterns = parse_url_filter_rules(rulelist_output.strip())

    # Find and remove the pattern
    if url_pattern.lower() not in [p.lower() for p in current_patterns]:
        return [
            TextContent(
                type="text",
                text=f"Error: URL pattern '{url_pattern}' not found in filter list",
            )
        ]

    # Remove the pattern (case-insensitive)
    updated_patterns = [p for p in current_patterns if p.lower() != url_pattern.lower()]

    # Build new rulelist
    new_rulelist = build_url_filter_rules(updated_patterns)

    # Set new rulelist
    router.execute_command(f'nvram set {NVRAM_URL_RULELIST}="{new_rulelist}"')
    router.execute_command("nvram commit")

    # Restart firewall to apply changes
    router.execute_command("service restart_firewall")

    result = "✓ URL Filter Removed\n\n"
    result += f"Pattern: {url_pattern}\n"
    result += f"Remaining rules: {len(updated_patterns)}/{URL_FILTER_MAX_RULES}\n"
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


def handle_list_url_filters(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    List all configured URL filter rules.

    Args:
        router: RouterSSHClient instance
        _arguments: Not used

    Returns:
        list[TextContent]: List of URL filter rules
    """
    # Get URL filter settings
    enable_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_ENABLE}")
    mode_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_MODE}")
    rulelist_output, _, _ = router.execute_command(f"nvram get {NVRAM_URL_RULELIST}")

    enabled = enable_output.strip() == "1"
    mode = mode_output.strip()
    mode_str = (
        "Whitelist (allow only)"
        if mode == URL_MODE_WHITELIST
        else "Blacklist (block listed)"
    )

    patterns = parse_url_filter_rules(rulelist_output.strip())

    result = "🌐 URL FILTER RULES\n\n"
    result += f"Status: {'✓ ENABLED' if enabled else '✗ DISABLED'}\n"
    result += f"Mode: {mode_str}\n"
    result += f"Total Rules: {len(patterns)}/{URL_FILTER_MAX_RULES}\n\n"

    if not patterns:
        result += "No URL filter rules configured.\n"
    else:
        result += "CONFIGURED PATTERNS:\n"
        for i, pattern in enumerate(patterns, 1):
            result += f"  {i}. {pattern}\n"

    return [TextContent(type="text", text=result)]


def handle_set_url_filter_mode(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Set URL filter mode (blacklist vs whitelist).

    Args:
        router: RouterSSHClient instance
        arguments: Dict with 'mode' key ('blacklist' or 'whitelist')

    Returns:
        list[TextContent]: Success message
    """
    mode = arguments.get("mode", "").strip().lower()

    if mode not in ["blacklist", "whitelist"]:
        return [
            TextContent(
                type="text", text="Error: Mode must be 'blacklist' or 'whitelist'"
            )
        ]

    nvram_value = URL_MODE_WHITELIST if mode == "whitelist" else URL_MODE_BLACKLIST

    # Set mode
    router.execute_command(f"nvram set {NVRAM_URL_MODE}={nvram_value}")
    router.execute_command("nvram commit")

    # Restart firewall
    router.execute_command("service restart_firewall")

    result = "✓ URL Filter Mode Updated\n\n"
    result += f"New Mode: {mode.capitalize()}\n"
    if mode == "blacklist":
        result += "  - URLs matching filter patterns will be BLOCKED\n"
        result += "  - All other URLs will be ALLOWED\n"
    else:
        result += "  - URLs matching filter patterns will be ALLOWED\n"
        result += "  - All other URLs will be BLOCKED\n"
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


# ============================================================================
# Keyword Filtering Tools
# ============================================================================


def handle_get_keyword_filter_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    Get keyword filter status and configuration.

    Args:
        router: RouterSSHClient instance
        _arguments: Not used

    Returns:
        list[TextContent]: Formatted status information
    """
    # Get keyword filter settings
    enable_output, _, _ = router.execute_command(f"nvram get {NVRAM_KEYWORD_ENABLE}")
    rulelist_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_KEYWORD_RULELIST}"
    )
    sched_output, _, _ = router.execute_command(f"nvram get {NVRAM_KEYWORD_SCHED}")

    enabled = enable_output.strip() == "1"
    rules = parse_keyword_list(rulelist_output.strip())
    rule_count = len(rules)

    result = "🔤 KEYWORD FILTER STATUS\n\n"
    result += f"Status: {'✓ ENABLED' if enabled else '✗ DISABLED'}\n"
    result += f"Keyword Rules: {rule_count}/{KEYWORD_FILTER_MAX_RULES}\n"
    result += f"Schedule: {sched_output.strip() or 'Always active'}\n"

    if rules:
        result += "\n📋 BLOCKED KEYWORDS:\n"
        for i, keyword in enumerate(rules, 1):
            result += f"  {i}. {keyword}\n"

    return [TextContent(type="text", text=result)]


def handle_add_keyword_filter(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Add keyword to filter list.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with 'keyword' key

    Returns:
        list[TextContent]: Success or error message
    """
    keyword = arguments.get("keyword", "").strip()

    if not keyword:
        return [TextContent(type="text", text="Error: Keyword is required")]

    # Get current rulelist
    rulelist_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_KEYWORD_RULELIST}"
    )
    current_rules = parse_keyword_list(rulelist_output.strip())

    # Check limit
    if len(current_rules) >= KEYWORD_FILTER_MAX_RULES:
        return [
            TextContent(
                type="text",
                text=f"Error: Maximum {KEYWORD_FILTER_MAX_RULES} keyword filter rules already configured",
            )
        ]

    # Check for duplicates
    if keyword.lower() in [k.lower() for k in current_rules]:
        return [
            TextContent(
                type="text",
                text=f"Error: Keyword '{keyword}' already exists in filter list",
            )
        ]

    # Add new keyword
    current_rules.append(keyword)

    # Build new rulelist
    new_rulelist = build_keyword_list(current_rules)

    # Set new rulelist and enable keyword filtering
    router.execute_command(f'nvram set {NVRAM_KEYWORD_RULELIST}="{new_rulelist}"')
    router.execute_command(f"nvram set {NVRAM_KEYWORD_ENABLE}=1")
    router.execute_command("nvram commit")

    # Restart firewall to apply changes
    router.execute_command("service restart_firewall")

    result = "✓ Keyword Filter Added\n\n"
    result += f"Keyword: {keyword}\n"
    result += f"Total keywords: {len(current_rules)}/{KEYWORD_FILTER_MAX_RULES}\n"
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


def handle_remove_keyword_filter(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Remove keyword from filter list.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with 'keyword' key

    Returns:
        list[TextContent]: Success or error message
    """
    keyword = arguments.get("keyword", "").strip()

    if not keyword:
        return [TextContent(type="text", text="Error: Keyword is required")]

    # Get current rulelist
    rulelist_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_KEYWORD_RULELIST}"
    )
    current_rules = parse_keyword_list(rulelist_output.strip())

    # Find and remove the keyword
    found = False
    updated_rules = []
    for k in current_rules:
        if k.lower() == keyword.lower():
            found = True
            continue
        updated_rules.append(k)

    if not found:
        return [
            TextContent(
                type="text", text=f"Error: Keyword '{keyword}' not found in filter list"
            )
        ]

    # Build new rulelist
    new_rulelist = build_keyword_list(updated_rules)

    # Set new rulelist
    router.execute_command(f'nvram set {NVRAM_KEYWORD_RULELIST}="{new_rulelist}"')
    router.execute_command("nvram commit")

    # Restart firewall to apply changes
    router.execute_command("service restart_firewall")

    result = "✓ Keyword Filter Removed\n\n"
    result += f"Keyword: {keyword}\n"
    result += f"Remaining keywords: {len(updated_rules)}/{KEYWORD_FILTER_MAX_RULES}\n"
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


def handle_list_keyword_filters(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    List all configured keyword filter rules.

    Args:
        router: RouterSSHClient instance
        _arguments: Not used

    Returns:
        list[TextContent]: List of keyword filters
    """
    # Get keyword filter settings
    enable_output, _, _ = router.execute_command(f"nvram get {NVRAM_KEYWORD_ENABLE}")
    rulelist_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_KEYWORD_RULELIST}"
    )

    enabled = enable_output.strip() == "1"
    rules = parse_keyword_list(rulelist_output.strip())

    result = "🔤 KEYWORD FILTER RULES\n\n"
    result += f"Status: {'✓ ENABLED' if enabled else '✗ DISABLED'}\n"
    result += f"Total Keywords: {len(rules)}/{KEYWORD_FILTER_MAX_RULES}\n\n"

    if not rules:
        result += "No keyword filters configured.\n"
    else:
        result += "BLOCKED KEYWORDS:\n"
        for i, keyword in enumerate(rules, 1):
            result += f"  {i}. {keyword}\n"

    return [TextContent(type="text", text=result)]
