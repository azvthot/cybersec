# Cybersecurity Tools

This lists explains various tools for cybersecurity, grouped by functionality. Each tool includes a detailed explanation of its usage and relevance to security tasks such as penetration testing, network analysis, forensics, and more.

## Information Gathering

*Tools for reconnaissance and collecting data about targets.*

**Nmap (Network Mapper)** *A powerful network scanning tool for discovering hosts, open ports, services, and operating systems on a network.*

**Wireshark** *A network protocol analyzer that captures and inspects packets in real-time for detailed traffic analysis.*

**Maltego** *A graphical tool for link analysis and data mining, useful for mapping relationships between entities like domains and IPs.*

**Recon-ng** *A web-based reconnaissance framework that leverages OSINT to gather information about targets.*

**theHarvester** *A tool for collecting email addresses, subdomains, and other data from public sources like search engines.*

**dnsrecon** *A DNS enumeration tool that identifies records, subdomains, and potential misconfigurations in DNS setups.*

**Fierce** *A domain scanner that maps network IP ranges and identifies hostnames, useful for corporate network reconnaissance.*

**Shodan (CLI)** *A command-line interface to the Shodan search engine, finding internet-connected devices and their details.*

**OSRFramework** *A set of tools for OSINT, linking usernames across platforms and gathering public data.*

**SpiderFoot** *An automated OSINT tool for gathering intelligence on IPs, domains, and networks.*

**Dmitry** *A deepmagic information gathering tool for collecting host data like subdomains and emails.*

**Netdiscover** *A network scanning tool for discovering active devices on a LAN via ARP requests.*

**Enum4linux** *A tool for enumerating SMB shares, users, and groups on Windows and Samba systems.*

**Snmpcheck** *A tool for enumerating SNMP-enabled devices and extracting configuration details.*

**Onesixtyone** *A fast SNMP scanner for identifying devices using community strings.*

## Scanning

*Tools for identifying vulnerabilities, open ports, and system weaknesses.*

**OpenVAS (Open Vulnerability Assessment System)** *A full-featured vulnerability scanner that detects security issues in networks, web apps, and databases.*

**Nessus Essentials** *A free vulnerability scanner identifying misconfigurations and threats (up to 16 IPs).*

**Nikto** *A web server scanner that checks for outdated software, dangerous files, and common vulnerabilities.*

**Skipfish** *A fast web application scanner that performs recursive crawls and dictionary-based probes for vulnerabilities.*

**Wapiti** *A web vulnerability scanner that uses injection techniques (e.g., SQL, XSS) to identify flaws in web apps.*

**Lynis** *A security auditing tool for Unix systems, scanning for configuration issues and risks.*

**XSSPY** *A Python-based tool focused on detecting cross-site scripting (XSS) vulnerabilities in websites.*

**DotDotPwn** *A fuzzer for discovering directory traversal vulnerabilities in web servers and applications.*

**Legion** *A semi-automated network penetration testing tool with vulnerability scanning capabilities.*

**Vega** *A web vulnerability scanner and testing platform with a GUI for finding XSS, SQLi, and more.*

**Arachni** *A high-performance web application scanner for detecting security flaws.*

**SSLyze** *A tool for analyzing SSL/TLS configurations and identifying weaknesses.*

**Nmap Scripting Engine (NSE)** *An extension of Nmap with scripts for advanced vulnerability detection and enumeration.*

**Golismero** *A web application scanner that integrates multiple tools for comprehensive analysis.*

**Masscan** *A high-speed port scanner for large-scale network reconnaissance.*

## Exploitation

*Tools for exploiting vulnerabilities to gain unauthorized access.*

**Metasploit Framework** *A penetration testing framework with exploits, payloads, and auxiliary modules for testing and exploiting systems.*

**SQLmap** *An automated tool for detecting and exploiting SQL injection vulnerabilities in databases.*

**Burp Suite (Community Edition)** *A web application testing suite with proxy, scanner, and intruder tools for exploiting web vulnerabilities.*

**Commix** *A tool for exploiting command injection vulnerabilities in web applications to execute OS commands.*

**Jexboss** *An exploitation tool targeting misconfigured JBoss servers to gain control over web servers.*

**BeEF (Browser Exploitation Framework)** *A tool for exploiting web browser vulnerabilities, focusing on client-side attacks.*

**Empire** *A post-exploitation framework using PowerShell and Python for maintaining access and escalating privileges.*

**RouterSploit** *A framework for exploiting vulnerabilities in embedded devices like routers and IoT systems.*

**Exploit-DB (SearchSploit)** *A local search tool for the Exploit Database, providing exploit code and PoCs.*

**Armitage** *A GUI front-end for Metasploit, simplifying exploit management and collaboration.*

**Pupy** *A cross-platform post-exploitation tool for remote administration and payload delivery.*

**SEToolkit (Social-Engineer Toolkit)** *A framework for crafting phishing attacks and exploiting human vulnerabilities (also under Social Engineering).*

**CrackMapExec** *A post-exploitation tool for enumerating and attacking Active Directory environments.*

**Shellter** *A dynamic shellcode injection tool for bypassing antivirus detection.*

## Password Attacks

*Tools for cracking or recovering passwords.*

**John the Ripper** *A fast, open-source password cracker supporting multiple hash types and dictionary attacks.*

**Hydra** *A brute-force tool for attacking login credentials across various protocols (e.g., SSH, FTP, HTTP).*

**Hashcat** *A high-performance password recovery tool optimized for cracking complex hashes with GPU support.*

**CeWL (Custom Word List Generator)** *A tool that spiders websites to create custom wordlists for password cracking.*

**Crunch** *A wordlist generator for creating custom password lists based on specified patterns.*

**RainbowCrack** *A tool that uses precomputed rainbow tables to speed up password hash cracking.*

**Medusa** *A parallel brute-force tool for cracking passwords on remote services.*

**Patator** *A multi-purpose brute-forcer for testing credentials across protocols and services.*

**Ophcrack** *A Windows password cracker using rainbow tables, with a GUI interface.*

**Hash-identifier** *A tool for identifying the type of hash from a given input.*

## Wireless Attacks

*Tools for testing and exploiting wireless networks.*

**Aircrack-ng** *A suite of tools for auditing Wi-Fi security, including packet capture, WEP/WPA cracking, and injection.*

**Kismet** *A wireless network detector and sniffer that identifies Wi-Fi networks and devices passively.*

**Reaver** *A tool for exploiting WPS weaknesses to recover WPA/WPA2 passphrases.*

**Fern Wifi Cracker** *A GUI-based tool for auditing and cracking Wi-Fi networks, supporting WEP/WPA attacks.*

**Wifite** *An automated tool for attacking multiple Wi-Fi networks, streamlining cracking processes.*

**Airgeddon** *A multi-use bash script for Wi-Fi auditing, including DoS and handshake capture.*

**MDK4** *A tool for wireless attacks like deauthentication and beacon flooding.*

**Pixiewps** *A tool for offline WPS PIN brute-forcing to crack Wi-Fi passwords.*

**Wifiphisher** *A rogue AP tool for phishing Wi-Fi credentials from users.*

## Web Application Analysis

*Tools focused on testing and securing web applications.*

**OWASP ZAP (Zed Attack Proxy)** *An open-source web app scanner with automated and manual tools for finding vulnerabilities.*

**WPScan** *A WordPress vulnerability scanner that identifies security issues in WordPress installations.*

**JoomScan** *A Joomla-specific scanner for detecting vulnerabilities in Joomla CMS websites.*

**CMSmap** *A tool for scanning and exploiting vulnerabilities in popular CMS platforms (WordPress, Joomla, Drupal).*

**Dirb** *A web content scanner that uses wordlists to discover hidden directories and files on web servers.*

**WhatWeb** *A web scanner that identifies technologies, CMS, and frameworks used by websites.*

**Gobuster** *A brute-forcing tool for discovering directories, files, and DNS subdomains.*

**Wfuzz** *A web fuzzer for finding hidden resources and testing input validation.*

**SQLninja** *A tool for exploiting SQL injection vulnerabilities on Microsoft SQL Server.*

**XSSer** *An automated tool for detecting and exploiting XSS vulnerabilities.*

## Post-Exploitation

*Tools for maintaining access and extracting data after exploitation.*

**Mimikatz** *A tool for extracting plaintext passwords, hashes, and Kerberos tickets from memory in Windows systems.*

**PowerSploit** *A collection of PowerShell scripts for post-exploitation tasks like privilege escalation and data theft.*

**Responder** *A tool for poisoning LLMNR, NBT-NS, and MDNS responses to capture credentials on a network.*

**BloodHound** *A tool for mapping attack paths in Active Directory, identifying privilege escalation opportunities.*

**Pwncat** *A post-exploitation tool for automating privilege escalation and data exfiltration.*

**Evilgrade** *A tool for injecting fake updates into software to maintain access.*

**LaZagne** *A password recovery tool for extracting credentials from browsers, email clients, and more.*

**Pupy** *A cross-platform remote administration tool for post-exploitation (also under Exploitation).*

**Koadic** *A Windows post-exploitation rootkit using COM for persistence and control.*

**Netcat** *A versatile networking tool for creating backdoors and transferring files (also under Miscellaneous).*

## Forensics

*Tools for digital forensics and evidence analysis.*

**Autopsy** *A GUI-based forensic tool for analyzing hard drives, recovering deleted files, and investigating logs.*

**Binwalk** *A tool for analyzing and extracting firmware images, useful in reverse engineering.*

**Bulk Extractor** *A scanner that extracts emails, URLs, and credit card numbers from disk images or files.*

**Xplico** *A network forensics tool that reconstructs and analyzes captured network traffic.*

**Guymager** *A disk imaging tool for creating forensic images in formats like EWF.*

**p0f** *A passive OS fingerprinting tool that identifies systems based on network traffic analysis.*

**pdf-parser** *A tool for parsing PDF files to detect hidden malicious code or suspicious elements.*

**Volatility** *A memory forensics framework for analyzing RAM dumps and extracting process data.*

**Foremost** *A tool for recovering files from disk images based on file headers and footers.*

**Scalpel** *A file carving tool for recovering deleted files from disk images.*

## Reverse Engineering

*Tools for analyzing and modifying software or firmware.*

**Apktool** *A tool for reverse engineering Android APK files to inspect and modify their contents.*

**Ghidra** *An open-source reverse engineering tool from the NSA for analyzing binaries and malware.*

**Radare2** *A command-line framework for reverse engineering, disassembling, and debugging binaries.*

**OllyDbg** *A debugger for analyzing Windows executables, useful for malware analysis.*

**dex2jar** *A tool for converting Android DEX files to JAR files for further analysis.*

**IDA Free** *A free version of the Interactive Disassembler for analyzing binary code.*

**Bytecode Viewer** *A GUI tool for decompiling and analyzing Java and Android bytecode.*

**JD-GUI** *A standalone graphical utility for decompiling Java class files.*

**Frida** *A dynamic instrumentation toolkit for reverse engineering and debugging applications.*

## Sniffing and Spoofing

*Tools for intercepting and manipulating network traffic.*

**Bettercap** *A tool for man-in-the-middle attacks, sniffing, and spoofing on various protocols.*

**Ettercap** *A suite for MITM attacks, including ARP spoofing and traffic interception.*

**Snort** *An open-source intrusion detection/prevention system for real-time traffic analysis.*

**Cain & Abel** *A Windows-based tool (usable via Wine) for sniffing passwords and spoofing network traffic.*

**dnsspoof** *A tool for forging DNS responses to redirect traffic to malicious destinations.*

**arpspoof** *A tool for ARP poisoning to intercept network traffic.*

**macchanger** *A utility for spoofing MAC addresses to evade network tracking.*

**Scapy** *A packet manipulation tool for crafting, sniffing, and spoofing network traffic.*

**TCPdump** *A command-line packet analyzer for capturing and inspecting network traffic.*

**Dsniff** *A collection of tools for sniffing passwords and spoofing network protocols.*

## Social Engineering

*Tools for testing human vulnerabilities.*

**SET (Social-Engineer Toolkit)** *A framework for crafting phishing attacks, fake websites, and other social engineering exploits.*

**PhishLulz** *A tool for generating phishing campaigns to test user awareness.*

**King Phisher** *A phishing campaign toolkit with templates for email-based social engineering attacks.*

**Gophish** *An open-source phishing framework for simulating real-world phishing attacks.*

**Evilginx2** *A man-in-the-middle attack framework for capturing credentials via phishing.*

## Stress Testing

*Tools for testing system resilience under load.*

**Slowloris** *A tool for launching low-bandwidth DoS attacks against web servers.*

**THC-SSL-DOS** *A tool for testing SSL/TLS servers by overwhelming them with renegotiation requests.*

**hping3** *A packet generator for stress testing networks with custom TCP/IP packets.*

**GoldenEye** *A HTTP DoS tool for testing web server resilience.*

**Torshammer** *A slow-rate HTTP DoS tool for overwhelming web servers.*

## Miscellaneous

*Tools with unique or broad applications.*

**Netcat** *A versatile networking tool for port scanning, file transfer, and creating backdoors.*

**Yersinia** *A framework for Layer 2 attacks on protocols like STP, CDP, and DHCP.*

**DHCPig** *A DHCP exhaustion tool to consume IP addresses on a LAN.*

**Cryptcat** *An encrypted version of Netcat for secure communication.*

**Socat** *A multipurpose relay tool for bidirectional data transfer between networks.*

**ProxyChains** *A tool for routing traffic through proxy servers to anonymize connections.*

**Tor** *A network for anonymous communication and browsing.*

**Aircrack-ng (Monitor Mode Setup)** *A tool for enabling monitor mode on wireless interfaces (also under Wireless Attacks).*

**Knockd** *A port-knocking server/client for opening ports via specific sequences.*