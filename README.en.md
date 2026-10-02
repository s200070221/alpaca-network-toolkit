# 🦙 Alpaca Network Toolkit

[繁體中文](README.md) | **English**

A set of browser-based tools for parsing, anonymizing, comparing and generating multi-vendor firewall and switch configurations. Everything is plain front-end JavaScript and works offline after download. **All parsing and processing happens locally in your browser — configuration files are never uploaded to any server.**

Try it online (no download needed): **https://s200070221.github.io/alpaca-network-toolkit/**

Or download this repository and open `network-analyzer.html` (the entry page for all six tools) in your browser.

## Tools

| Tool | Files | Description |
|---|---|---|
| 🛡️ Firewall Config Analyzer | `firewall-analyzer-fixed.html` + `firewall-analyzer-*.js` (25 module files) | Parses FortiGate / Sophos XG / Check Point / Palo Alto / Juniper SRX / pfSense / OPNsense / SonicWall / MikroTik / Cisco ASA/FTD / Zyxel USG-ATP / EdgeRouter (EdgeOS) / OpenWrt (UCI) / WatchGuard Firebox / VyOS / Linux iptables・nftables configurations, plus AWS security groups / Azure NSGs / Cisco Meraki MX (API response JSON) — 18 sources in total. Visualizes rules, routes, NAT, VPN and address objects; supports IP/port lookup, shadowed-rule analysis, compliance audit with a health score, old-vs-new (or HA primary/secondary) config comparison, and conversion between config formats. For FortiGate / Cisco ASA/FTD / Palo Alto / Juniper SRX you can also paste rule hit counts to find rules that have never been hit or not been hit for a long time |
| 🔀 Switch Config Parser | `switch-config-parser.html` + `switch-analyzer-*.js` (29 module files) | Parses 21 vendors: HPE Comware / Cisco IOS-XE / NX-OS / Cisco Business (CBS/SG) / Aruba CX / ProCurve / FortiSwitch / Juniper EX/QFX / Extreme / Alcatel OmniSwitch / Ruckus-Brocade ICX / Dell OS10 / Arista EOS / MikroTik RouterOS / Ruijie RGOS / Netgear M4300 / Ubiquiti EdgeSwitch / SONiC / Planet / Allied Telesis AlliedWare Plus / NVIDIA Cumulus Linux (NVUE). Visualizes ports, VLANs, routing and stack topology, with a security audit and health score, config comparison, a cabling sheet and endpoint lookup (MAC / ARP tables) |
| 🛠️ Switch Config Generator | `switch-config-generator.html` + `switch-generator-*.js` (23 module files) | Generates switch configurations from a form for 18 vendors (Comware / FortiSwitch / Aruba CX / Cisco IOS-XE / Juniper / Dell OS10 / NX-OS / Arista / Brocade ICX / Alcatel / Extreme / ProCurve / RouterOS / Ruijie / Netgear / EdgeSwitch / SONiC / Planet), including IPv6, secondary IPs, OSPF/OSPFv3, BGP, VRRP, ACL, QoS and stacking. Supports CSV batch generation and a template library, and can import an existing configuration back into the form (or receive it directly from the Switch Config Parser) |
| 🔒 Config Anonymizer | `config-anonymizer.html` | Supports 35 firewall / switch / cloud config formats. Consistently replaces IPs, hostnames, user names, passwords, keys, SNMP communities, MAC addresses and other sensitive data so a config can be shared or posted when asking for help. Can optionally preserve subnet structure (addresses in the same subnet map to the same fake subnet, so lookups and routing results stay the same), check that the structure is unchanged after anonymization, and save the mapping table encrypted with AES-256 for later restoration. Full IPv4/IPv6 support |
| 📜 Log Analyzer & Anonymizer 🧪 experimental | `log-analyzer.html` | Imports switch / firewall / server logs (CEF, LEEF, standard Syslog RFC3164/RFC5424, FortiGate key=value, Cisco ASA, Cisco IOS / Comware device logs, Juniper SRX RT_FLOW, MikroTik, Linux iptables/nftables LOG, Windows event XML and Sysmon, AWS VPC / Azure NSG flow logs, IIS / web access logs, JSON). Sorts by severity and flags likely problems (frequency anomalies, scans, authentication failures, Kerberoasting, lateral movement, interface problems, MAC flapping, multi-stage attack chains and more, tagged with MITRE ATT&CK IDs). Supports local threat-intel and ASN list matching (local only, no network access), anonymization of sensitive fields, and CSV / report export. An event can be sent to the Firewall Analyzer to find the matching rule, and an interface problem can be sent to the Switch Config Parser to view that port. `fetch_threat_intel.ps1` is an optional standalone helper that downloads public blocklists outside the browser and merges them into one file for import; the tool itself stays offline |
| 🌐 Entry Page | `network-analyzer.html` | Detects the vendor of a dropped file and opens the matching tool |

> Some tools load their JavaScript from separate `.js` files (classic `<script src>`, not ES modules), so they work both when opened directly from disk (`file://`) and on GitHub Pages. **When downloading or sharing these tools, keep the `.js` files in the same folder as the `.html` file** — a single `.html` file on its own will not work, so downloading the whole repository is recommended. If you need a true single-file version (for example, to send as one attachment), run `build-standalone.ps1` to produce merged single-file builds in `dist/`.

## User guides

The `docs/` folder contains detailed user guides (.docx, currently in Traditional Chinese only): [Firewall Config Analyzer](docs/firewall-analyzer-guide.docx) / [Switch Config Parser](docs/switch-config-parser-guide.docx) / [Switch Config Generator](docs/switch-config-generator-guide.docx) / [Config Anonymizer](docs/config-anonymizer-guide.docx) / [Entry Page](docs/network-analyzer-guide.docx) / [Log Analyzer & Anonymizer](docs/log-analyzer-guide.docx).

How the tools hand data to each other (for example, sending a log event to the Firewall Analyzer to find the matching rule, sending an interface problem to the Switch Config Parser, or forwarding an anonymized config to an analysis tool), and what you need to prepare for each, is described in the [tool integration guide](docs/tool-integration-guide.docx).

## Highlights

- **No server, no install**: plain JS + HTML — download and use, or open it online via GitHub Pages
- **Multilingual UI**: Traditional Chinese / English / Japanese (plus several hidden easter-egg languages)
- **Broad vendor coverage**: 18 firewall sources (including AWS / Azure / Meraki cloud), 21 switch vendors, and 35 config formats for anonymization

## License and usage restrictions

This repository does **not** grant any open-source license. Content is provided for viewing and personal evaluation only — copying, modification, redistribution and commercial use are **not permitted** without explicit permission from the author.

## Disclaimer

All configuration text exported or generated by these tools is for reference only. Review and verify it carefully before applying it to any device; you use it at your own risk.
