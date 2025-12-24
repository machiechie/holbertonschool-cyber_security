Linux Security Basics


The File System Hierarchy (FHS) in Depth

Linux uses a unified directory structure. Unlike Windows, which uses drive letters (C:, D:), everything in Linux starts at the root (/). This consistency allows security tools and scripts to work across different versions (distributions) of Linux.


Security-Critical Directories

/bin and /usr/bin
Hold basic user commands such as ls and cp.
Security concern: If an attacker replaces these binaries, they can hijack common commands.

/sbin and /usr/sbin
Contain system administration binaries such as iptables or reboot.
These usually require root privileges to run.

/etc
The most important directory for configuration files.
/etc/passwd stores user account information.
/etc/shadow stores encrypted passwords and is accessible only by root.

/boot
Contains the kernel (the brain of the OS) and files needed to start the system.
If this directory is compromised, the entire OS becomes untrustworthy from boot time.

/proc and /sys
Virtual filesystems that do not exist on disk.
They provide a window into the kernel and running processes.


Process Management and Termination

A process is a program in execution. Monitoring processes helps detect malicious software running in the background.


Identification Commands

ps aux
Shows every running process.
a = all users, u = user-oriented format, x = processes without a terminal.

top / htop
Interactive process monitors.
If a process unexpectedly uses 100% CPU, it is a red flag.


Termination Commands (Kill Signals)

When you kill a process, you send it a signal.

kill PID
Sends SIGTERM (15). A polite request to save work and shut down.

kill -9 PID
Sends SIGKILL (9). Immediate forced termination by the kernel, no cleanup.

pkill name
Kills processes by name if you do not know the PID, for example: pkill firefox.


Network Security and Monitoring

In cybersecurity, visibility is defense. You must know which ports are open on your system.

netstat -tuln or ss -tuln
Show listening ports.
t = TCP, u = UDP, l = listening, n = numeric addresses.
Security check: If you see an unexpected open port (for example 4444), it may be a backdoor.

nmap
Network Mapper. Scans a system from the outside to show what an attacker would see.

tcpdump
Packet sniffer. Captures raw network traffic so you can analyze suspicious behavior.


The Defensive Wall: Firewalls

Linux uses a framework called Netfilter to filter packets. It is managed with tools like iptables or UFW.

iptables (professional and granular)

Uses chains to decide a packets fate:
INPUT traffic coming into your system.
FORWARD traffic passing through your system (if acting as a router).
OUTPUT traffic leaving your system.

UFW (easy and simple)

UFW (Uncomplicated Firewall) is a wrapper for iptables with simpler syntax:
sudo ufw enable enable the firewall.
sudo ufw deny 22 block SSH access.


Advanced Security Tools

chroot (jailing)
Changes the root directory for a process, creating a chroot jail.
If a web server is compromised inside a jail, the attacker only sees that folder and cannot access the real system.

auditd
The black box recorder of Linux.
Logs who changed files, who logged in, and which commands were executed.

lynis
A security auditing tool.
Scans the system and provides a hardening index with recommendations to improve security.


-------------------------------------------------------------------------------------------------------


TASKS


0. What secrets hold

The Logic
The last command by default shows all recorded logins. To meet the requirements of your script, you need to:

Limit the output: Use a flag to specify exactly 5 lines of history.

Ensure Privileges: Since /var/log/wtmp is a system file, running the script with sudo is best practice to ensure it has read access (though on many systems, last is world-readable).

The Script

#!/bin/bash
# A script to display the last 5 login sessions
last -n 5

last: The command that looks into the binary log file /var/log/wtmp to find login/logout history.

-n 5: This flag (or simply -5 on most versions) limits the output to the most recent 5 entries.



1. Shows your Linux connections, not your social status!

Based on your requirements, here is the breakdown of the flags needed:

Show all sockets (listening and non-listening): -a

Display numerical addresses: -n

Limit to TCP: -t

Display process information: -p

The Script
#!/bin/bash
# A script that displays active and listening TCP connections with process info
ss -atnp

ss: The modern replacement for netstat provided by the iproute2 package.

-a (All): By default, ss only shows established connections. This flag forces it to include "Listening" ports (like your SSH server waiting for a connection).

-t (TCP): Filters the output to only show Transmission Control Protocol sockets, ignoring UDP or Unix sockets.

-n (Numeric): Prevents ss from trying to resolve IP addresses to hostnames or port numbers to service names (e.g., shows 22 instead of ssh). This is safer in security contexts as it avoids DNS leaks/delays.

-p (Process): Attempts to identify the Process ID (PID) and the name of the program owning the socket.



2. Firewall rules: Your network's first line of defense!

The Logic
Based on your requirements, the script needs to:

Filter by Protocol: Only allow TCP.

Filter by Port: Only port 80 (HTTP).

Direction: Incoming connections.

The Script
#!/bin/bash
# A script that allows incoming TCP traffic on port 80
ufw allow 80/tcp

ufw: The command-line interface for managing the firewall.

allow: The action to take. This tells the firewall to permit the packet.

80/tcp: This is the specific rule.

80: The port number used for standard, unencrypted web traffic (HTTP).

/tcp: This is a critical security constraint. It ensures that only TCP packets are allowed. Any UDP packets sent to port 80 will still be blocked by the default policy.


The Command: ufw
Context: ufw stands for Uncomplicated Firewall. It is a "front-end" or "wrapper" for iptables.
Why use it? While iptables is very powerful, its syntax is complex and prone to human error. ufw simplifies the process of defining rules, which reduces the chance of a misconfiguration that could leave your server vulnerable.



3. Securing your network, one rule at a time!

The Logic
Based on your project requirements:

The Table: You must specify the security table. While filter is the default table in iptables, the security table is used for Mandatory Access Control (MAC) networking rules (often linked to SELinux).

Verbose Mode: Use the -v flag. This adds columns for pkts (packets) and bytes, allowing you to see how much traffic has hit each rule.

Privilege: Firewall commands always require root or sudo because they interact directly with the Kernel's network stack.

The Script
#!/bin/bash
# A script that lists all rules in the security table in verbose mode
iptables -t security -L -v

iptables: The administration tool for IPv4 packet filtering and NAT.

-t security: This selects the specific security table. Linux netfilter has several tables:

filter: The default for basic firewalling.

nat: For port forwarding.

mangle: For specialized packet alteration.

security: Used for security marks and MAC (Mandatory Access Control) rules.

-L: Stands for List. It displays all the rules in the selected table.

-v: Stands for Verbose. As seen in your example output, this is what generates the pkts and bytes headers. It provides a "traffic counter" for every rule, which is vital for seeing if a security rule is actually catching any malicious traffic.

Why Verbose Mode is a Security Basic
In a security audit, simply knowing a rule exists isn't enough. By using verbose mode (-v), an administrator can see if a "Deny" rule has 0 packets or 1,000,000 packets. If a rule meant to block an attacker shows a high packet count, it tells you that an active attack is currently being deflected by that rule.



4. See what's talking, and who's listening!

The Logic
Based on your project requirements, here are the flags we will combine:

List Listening sockets: -l

Display TCP sockets: -t

Display UDP sockets: -u

Show PID and Program name: -p

Display numerical addresses: -n

The Script
#!/bin/bash
# A script to list services, states, and ports using netstat
netstat -ltupn

netstat: Short for "Network Statistics." It is the core tool for auditing which services are "listening" for incoming connections.

-l (Listening): Limits the output to sockets that are currently in the LISTEN state (for TCP) or active (for UDP).

-t (TCP) & -u (UDP): These filters ensure you see both types of internet protocols, covering everything from web servers (TCP) to DNS or DHCP clients (UDP).

-p (Program): This is the critical "Security" flag. It links the network port to a specific process on the machine. If you see an unknown process name here, it is an immediate red flag.

-n (Numeric): Forces the output to show IP addresses and port numbers as digits. This prevents the system from doing a reverse DNS lookup, which makes the script faster and more reliable in a forensic situation.



5. Where it talks, we all listen!

The Logic
Based on the terminal output provided in the requirements:

The Tool: You need to call lynis.

The Command: The audit system command is the standard way to perform a full system scan.

Privilege: Auditing tools must be run with sudo or as root because they need to read protected system configuration files (like /etc/shadow or kernel parameters) that are inaccessible to regular users.

The Script
#!/bin/bash
# A script that initiates a Lynis system audit
lynis audit system

lynis: The name of the auditing engine.

audit system: This specific argument tells Lynis to perform a local security scan. It covers categories such as:

System Tools: Checks for suspicious binaries or missing security patches.

Boot & Services: Checks the bootloader and which services start at boot.

Users & Groups: Looks for accounts with empty passwords or excessive permissions.

Networking: Audits firewall rules and listening ports.

Hardening: Checks if specific kernel security features (like ASLR) are enabled.



6. Your eyes and ears on the network!

The Logic
Based on the terminal output and the requirements provided:

The Tool: tcpdump is required for live packet capture.

The Interface: The output shows traffic from both eth0 and lo (localhost). Therefore, we should listen on any available interface.

Packet Limit: The -c (count) flag must be used to stop the capture after exactly 5 packets.

Privilege: Like all network sniffing tasks, this must be run with sudo to access the raw network socket.

The Script
#!/bin/bash
# A script that captures and analyzes the first 5 network packets
tcpdump -c 5 -i any

tcpdump: The command-line packet analyzer.

-c 5: This is the Count flag. It tells the program to exit automatically after it has captured 5 packets. Without this, tcpdump would run forever until you manually stopped it with Ctrl+C.

-i any: This specifies the Interface. Using any allows the tool to capture traffic from the Ethernet (eth0), Wi-Fi (wlan0), and the Loopback (lo) interfaces simultaneously.



7. So fast, it'll make your router sweat!

The Logic
Based on your project requirements and the example output:

The Tool: nmap is the command used for the scan.

The Argument: The script uses $1 to take the subnetwork or hostname (like www.holbertonschool.com) from the command line.

Privilege: Running Nmap with sudo allows it to use raw packets, which makes the scan faster and allows for more advanced techniques (like stealth SYN scans).

The Script
#!/bin/bash
# A script that scans a subnetwork or host provided as an argument
nmap "$1"

nmap: The core utility. By default, when no specific flags are added, Nmap scans the top 1,000 most common TCP ports and checks if the host is "up."

"$1": This is a positional parameter. In your example command ./7-scan.sh www.holbertonschool.com, the domain www.holbertonschool.com becomes the value of $1. The quotes ensure that the argument is handled correctly even if it contains special characters.

