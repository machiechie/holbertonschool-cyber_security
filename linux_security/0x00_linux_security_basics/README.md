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


