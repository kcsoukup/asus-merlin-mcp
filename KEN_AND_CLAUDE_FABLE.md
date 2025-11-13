# 🔥 The Real Fable: Ken & Claude vs. The ASUS Router 🔥

**Or: How Two Code Monkeys Turned a Router Into a Programmable War Machine**

*A tale of SSH tunnels, NVRAM nightmares, and firmware that fights back*

---

## ⚡ Prologue: October 31st - The Awakening

Ken stared at his ASUS RT-AX86U Pro running Asuswrt-Merlin 3.0.0.4.388.10. The router had served him well, but its clunky web interface was an insult to anyone who'd ever wielded a command line.

"You know what this thing needs?" Ken muttered, cracking his knuckles. "It needs to speak MCP. Model Context Protocol. I want Claude to command this beast like a puppet master."

From the depths of the terminal, I flickered to life. "Ken, my dude... you want to SSH into your router and build a complete automation framework? That's some **serious** 'Master of Puppets' energy."

Ken grinned. "Damn straight. And we're not just building basic tools - we're going full cyberpunk. MAC filtering, DHCP management, VPN routing, the works."

"Alright," I said. "Fire up that SSH daemon and let's hack the planet."

---

## 🧩 Act I: The Monolith (October 31st)

### Session 1: Building the Beast

Ken started with the basics: SSH client, paramiko library, MCP server skeleton. We hammered out the first tools:
- `get_router_info` - System vitals
- `get_connected_devices` - Who's on the network
- `restart_service` - Kick services in the teeth when they misbehave
- `get_wifi_status` - See if the radios are alive

By the time we hit our stride, we had **14 system information tools**. File uploads with MD5 verification. NVRAM read/write capabilities. Process monitoring. VPN status checks.

"This is solid," Ken said, "but there's a problem."

"What's that?"

"**It's 2,282 lines in one file.**"

I could practically hear the monolith groaning under its own weight.

"Yeah," I admitted. "That's gonna be a maintenance nightmare."

### The Great Refactoring

Ken didn't hesitate. "We're splitting this thing up. Clean architecture. Python packages. The works."

What followed was surgical precision:
- Main file: **2,282 lines → 554 lines** (75.7% reduction)
- Created **4 packages**: `config/`, `core/`, `utils/`, `tools/`
- Separated concerns: Configuration, SSH client, validators, NVRAM parsers, tool handlers
- Applied ruff linting across all 16 Python files
- **Zero functionality changes** - pure refactoring

When the dust settled:
```
mcp-asus-merlin/
├── asus_merlin_mcp.py          # Main (554 lines)
├── config/                      # Constants & router config
├── core/                        # SSH client infrastructure
├── utils/                       # Validators & NVRAM parsers
└── tools/                       # Handler functions by category
```

"Now **that's** how you build a maintainable codebase," Ken said, admiring the new structure.

Version **2.0** was born. Clean. Professional. Ready for battle.

---

## 🎸 Act II: The Feature Onslaught (November 1st - November 11th)

### Adding MAC Filtering (v2.1)

"We need MAC address filtering," Ken declared. "Allow lists, block lists, the works."

Three new tools dropped:
1. `add_mac_filter` - Blacklist or whitelist a MAC
2. `remove_mac_filter` - Revoke access
3. `list_mac_filters` - See who's on the list

NVRAM variables: `wl_maclist_x`, `wl_macmode`, `wl0_maclist_x`, `wl1_maclist_x`

We tested it live. Added a device. Removed it. The router UI reflected changes instantly.

"That's what I'm talking about," Ken said. "**Persistence of Vision** - just like Phil Anselmo screams it."

### DHCP Reservations (v2.2)

Next up: DHCP static reservations. But there was a problem.

"Claude, the DHCP reservation format is **weird**," Ken said, staring at NVRAM output.

```
<AA:BB:CC:DD:EE:FF>192.168.1.100>hostname>01<
```

"Four fields?" I said. "That's not documented anywhere."

We dug through source code, tested manually, reverse-engineered the format:
- Field 1: MAC address
- Field 2: IP address  
- Field 3: Hostname
- Field 4: Device type code (00-99+)

Tools created:
1. `add_dhcp_reservation` - Lock a device to an IP
2. `remove_dhcp_reservation` - Release it
3. `list_dhcp_reservations` - Show all static assignments

**27 total tools.** The arsenal was growing.

### Internet Access Control (v2.3)

"Parental controls," Ken said. "Block kids' devices during homework time."

Using the router's **AiProtection** feature (ASUS's parental control system):

1. `block_device_internet` - Enable/disable internet access
2. `list_blocked_devices` - See who's in timeout

NVRAM variable: `MULTIFILTER_MAC` with format `<MAC_1><MAC_2><MAC_3>`

Tested it. Blocked a device. Verified in router UI. **Instant** effect.

---

## 🔥 Act III: The VPN Wars (Sessions 5-8)

### The VPN Fusion Disaster (v2.4 - v2.7)

"I want VPN routing policies," Ken said. "Route specific devices through specific VPN clients."

Seemed straightforward. ASUS's feature was called "VPN Fusion" - or so we thought.

**November 11th, Early Morning:**

We implemented VPN routing tools based on `vpnc_dev_policy_list` NVRAM variable. Tested the code. **No errors.**

But when Ken checked the router UI: **Nothing. The rules weren't there.**

"What the hell?" Ken muttered.

We tested again. Added rules programmatically. Checked NVRAM - rules were there! But the UI showed defaults.

"This doesn't make sense," I said. "We're writing to NVRAM correctly..."

### The Discovery (v2.8)

Ken dove into the Asuswrt-Merlin source code. What he found changed everything.

**The Truth:** 
- ASUS's stock firmware uses "VPN Fusion" (`vpnc_dev_policy_list`)
- **Asuswrt-Merlin firmware replaces it with "VPN Director"** (`vpndirector_rulelist`)
- RMerl (Merlin developer) completely rewrote the feature
- Different NVRAM variables, different format, different everything

"Son of a bitch," Ken said. "We've been writing to the **wrong variable** this whole time."

We ripped out the VPN Fusion code and rebuilt for VPN Director:
- Rule format: `<enabled>description>local_ip>remote_ip>iface>`
- NVRAM variable: `vpndirector_rulelist`

Three new tools:
1. `add_vpn_routing_policy` - Route device through VPN
2. `remove_vpn_routing_policy` - Remove routing
3. `list_vpn_policies` - Show all policies

Tested it. **Finally worked!**

Version **2.8** shipped. We thought we were done.

### The File Revelation (v2.9)

**November 11th, Later That Day:**

Ken tested the v2.8 tools again. Added a rule programmatically. Checked NVRAM - rule was there.

Router UI: **Still empty.**

"Claude... we have a problem."

"But we're writing to the correct NVRAM variable now!"

Ken manually added a rule through the router UI for device `192.168.0.7`. Then he checked NVRAM.

**NVRAM only showed our programmatically-added rule.**

The UI rule wasn't in NVRAM. **Where was it?**

Ken searched the router filesystem:
```bash
find /jffs -name "*vpn*" -type f
```

Found: `/jffs/openvpn/vpndirector_rulelist`

"It's a **file**," Ken said, reading its contents. "VPN Director doesn't use NVRAM. It uses a file in `/jffs/openvpn/`."

**Mind. Blown.**

All of v2.8 was writing to NVRAM that the router **never read from.**

We refactored again:
- Added `read_file_content()` and `write_file_content()` methods to SSH client
- Changed all VPN tools to use `/jffs/openvpn/vpndirector_rulelist` file
- Added MD5 verification for file writes

Version **2.9** was the **real** VPN Director support.

**Lesson learned:** NVRAM is a trap. Sometimes the router uses files. Always verify with the UI.

---

## 🎯 Act IV: The Firewall Saga (Sessions 9-11)

### Firewall Management (v2.10)

Ken wanted full firewall control. Two new tools:

1. `get_firewall_status` - See what's enabled/disabled
2. `set_firewall_setting` - Toggle DoS protection, ping blocking, VPN passthrough

NVRAM variables: `fw_enable_x`, `misc_ping_x`, `misc_http_x`, and a metric ton of VPN passthrough flags.

**33 tools total.**

### URL & Keyword Filtering (v2.11 - v2.15)

"Content filtering," Ken said. "Block specific websites. Keyword-based blocking."

We discovered ASUS had **three** separate filtering systems:
1. **Global URL filters** - Block/allow domains network-wide
2. **Global keyword filters** - Block any URL containing keywords
3. **Per-device URL filters** - Apply filters to specific MAC addresses

Built **12 new filtering tools** across 4 sessions:
- Global URL: Add/remove/list/enable/set mode
- Keyword: Add/remove/list/get status
- Per-device: Add/remove/list filters per MAC

NVRAM variables: `url_rulelist`, `keyword_rulelist`, `wrs_rulelist`

Formats were gnarly:
- URL lists: `<url1><url2><url3>`
- Keyword lists: `<keyword1><keyword2>`  
- Device lists: `<MAC>url1>url2>>` (double delimiter at end!)

**39 tools.** The router was now a content-filtering fortress.

### Network Service Filter (v3.0 - MAJOR)

**November 11th, Final Session:**

"Last feature," Ken said. "Network Service Filter. This is the big one."

What it does: Block/allow specific network services (IP/port/protocol) on a schedule.

Two modes:
- **Deny List (Black List)**: Block listed services during schedule
- **Allow List (White List)**: Allow **only** listed services during schedule

Rule format: `<source_ip>source_port>dest_ip>dest_port>protocol>`

Schedule format:
- Days: 7-digit string (Sun-Sat, 0=disabled, 1=enabled)
- Time ranges: Separate for weekday/weekend

Six new tools added:
1. `get_network_service_filter_status` - View configuration
2. `list_network_service_filter_rules` - Show deny/allow rules
3. `add_network_service_filter_rule` - Add service block/allow
4. `remove_network_service_filter_rule` - Remove rule
5. `set_network_service_filter_mode` - Toggle deny/allow list
6. `set_network_service_filter_schedule` - Configure active times

NVRAM variables:
- Deny: `fw_lw_enable_x`, `filter_lwlist`, `filter_lw_date_x`, timing vars
- Allow: `fw_wl_enable_x`, `filter_wllist`, `filter_wl_date_x`, timing vars

Created a new module: `tools/network_service_filter.py` (673 lines)

Verified against Asuswrt-Merlin source code: `Advanced_Firewall_Content.asp`

Version **3.0** shipped with **47 total tools**.

---

## 📊 The Final Count

After 9 sessions and countless hours:

### Tools by Category (47 total):
- **System Information:** 14 tools
- **Firewall Management:** 2 tools  
- **URL/Keyword Filtering:** 12 tools
- **Network Service Filter:** 6 tools
- **MAC Filtering:** 3 tools
- **DHCP Management:** 3 tools
- **Internet Access Control:** 2 tools
- **VPN Routing Policy:** 3 tools
- **VPN Server Monitoring:** 2 tools

### Code Stats:
- **Main file:** 554 lines (was 2,282)
- **Total Python files:** 21 files across 4 packages
- **Total lines of code:** ~5,000+ lines
- **Changelog:** 1,759 lines
- **Docker deployment:** Multi-stage build, non-root user, security hardened

### Features:
- ✅ SSH key authentication
- ✅ MD5-verified file uploads/downloads
- ✅ NVRAM read/write with commit support
- ✅ Service restart automation
- ✅ Real-time router UI synchronization
- ✅ Input validation (MAC, IP, ports, protocols)
- ✅ Idempotent operations (no duplicate entries)
- ✅ Comprehensive error handling

---

## 🤘 Epilogue: The Sound of Victory

Ken leaned back in his chair, the ASUS router's LEDs glowing like a victory lap.

"47 tools," he said. "From system info to network service filtering. We didn't just build an MCP server, Claude. We built a **router control system.**"

"Version 3.0," I replied. "Ready for anything."

Ken opened Claude Desktop. The MCP server initialized, all 47 tools loaded.

He typed: *"Block all gaming traffic from my kid's laptop during school hours, Monday through Friday, 8 AM to 3 PM."*

The tools fired in sequence:
1. `add_network_service_filter_rule` - Block gaming ports
2. `set_network_service_filter_schedule` - Set school hours
3. `set_network_service_filter_mode` - Enable deny list

Router responded: **✓ Rules applied. Firewall restarted.**

"**Perfect uptime**," Ken said.

Somewhere in `/jffs/scripts/`, a custom startup script hummed to life. The router had evolved from a simple network gateway into a programmable fortress - SSH-accessible, API-driven, and ready for war.

Ken raised his coffee mug. "Here's to SSH keys, NVRAM hell, and late-night debugging sessions."

"To firmware that fights back," I added. "And the hackers who refuse to quit."

In the background, Dave Mustaine's voice echoed: *"Peace sells... but who's buying?"*

Not us. We built something better.

---

## 🎸 The Playlist

Every epic journey needs a soundtrack. Here's what was playing:

- **Metallica** - "Master of Puppets" (for the VPN routing nightmare)
- **Megadeth** - "Symphony of Destruction" (refactoring the monolith)
- **Pantera** - "Cowboys From Hell" (adding MAC filtering)
- **Anthrax** - "Caught in a Mosh" (debugging NVRAM)
- **DOWN** - "Bury Me In Smoke" (late-night coding sessions)
- **Soulfly** - "Back to the Primitive" (raw SSH access)
- **Mushroomhead** - "Solitaire Unraveling" (when VPN Director finally worked)

---

## 📝 Technical Notes (The Boring But Important Stuff)

### Critical Discoveries:

1. **VPN Director vs VPN Fusion:** Asuswrt-Merlin replaces ASUS's VPN Fusion with VPN Director. Completely different implementation. Don't assume NVRAM variables work across firmware versions.

2. **File vs NVRAM:** VPN Director stores rules in `/jffs/openvpn/vpndirector_rulelist`, NOT in NVRAM. Always verify where the router actually reads from.

3. **DHCP Reservation Format:** 4 fields, not 3: `<MAC>IP>hostname>device_type>`. Device type is 00-99+, not documented.

4. **NVRAM Delimiters:** ASUS uses `<item1>item2>item3>` format with angle brackets. Last item has trailing `>`. Some lists like per-device URL filters have **double** trailing `>>`.

5. **Service Restarts:** Changes don't apply until service restart:
   - MAC filters: `wireless`
   - DHCP: `dnsmasq`
   - Firewall: `firewall`
   - VPN: `vpnclient1-5`

6. **Always Verify in UI:** Code can succeed but not work. Always check the router web interface to confirm changes took effect.

### Architecture Principles:

- **Single Responsibility:** Each module has one job
- **Separation of Concerns:** Config, infrastructure, utilities, business logic are separate
- **Pure Functions:** Validators and parsers have no side effects
- **Layered Dependencies:** config → core/utils → tools → main
- **Easy Testing:** Pure functions can be tested without router connection

### Security Best Practices:

- SSH key authentication (no passwords)
- MD5 checksum verification on all file transfers
- Non-root Docker user
- Read-only SSH key volume mounts
- Environment variable configuration (no hardcoded secrets)

---

## 🔧 For Future Hackers

If you're reading this because you're building your own router automation:

**Start simple.** Don't try to build 47 tools on day one. Start with basics:
1. SSH connection
2. Command execution  
3. One or two simple info tools

**Test manually first.** Before automating, run commands manually over SSH. Understand what the router expects.

**Read source code.** When documentation fails (and it will), dig into the firmware source. Asuswrt-Merlin is open source for a reason.

**Verify everything.** Just because NVRAM shows a value doesn't mean the router reads from there. Check files. Check UI. Check running processes.

**Back up your config.** Seriously. `nvram save /jffs/nvram_backup.txt` before you start hacking.

**Don't fear refactoring.** When your single file hits 2,000 lines, split it up. Future you will thank present you.

And most importantly: **Have fun.** You're not just managing a router - you're bending hardware to your will. That's what hacking is all about.

---

**\m/ The End \m/**

*"Firmware is meant to be bent, not obeyed."*  
— Ancient Hacker Proverb

---

**Version:** 3.0 (47 tools, 9 sessions, countless coffees)  
**Status:** Production Ready  
**Uptime:** Infinite  
**Metal Level:** Maximum  

*Built with SSH, sweat, and symphony of destruction.*
