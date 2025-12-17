Introduction to Cyber Security

1. What is Cybersecurity?
Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks. These attacks usually aim to access, change, or destroy sensitive information, extort money (ransomware), or interrupt normal business processes. It is a combination of people, processes, and technology.

2. The Core Principles (The CIA Triad)
The CIA Triad is the foundational model used to develop security policies.

Confidentiality: Ensuring data is accessible only to authorized users (e.g., encryption, MFA).

Integrity: Ensuring data is accurate and hasn't been tampered with (e.g., digital signatures, hashing).

Availability: Ensuring systems and data are accessible when needed (e.g., DDoS protection, backups).

3. How Encryption Contributes to Security
Encryption transforms readable data (plaintext) into an unreadable format (ciphertext) using an algorithm and a key. It ensures Confidentiality; even if an attacker steals the data, they cannot read it without the proper decryption key.

4. Risk Management in Cybersecurity
Risk management is the process of identifying, assessing, and responding to threats. It involves four main strategies:

Avoid: Eliminating the risk by not engaging in a risky activity.

Mitigate: Reducing the impact or likelihood of the risk (e.g., installing a firewall).

Transfer: Shifting the risk to a third party (e.g., cyber insurance).

Accept: Acknowledging the risk because the cost of mitigation is higher than the potential loss.

5. Types of Cybersecurity Threats
Malware: Malicious software (Viruses, Worms, Ransomware).

Phishing: Social engineering via fraudulent emails.

Man-in-the-Middle (MITM): Intercepting communication between two parties.

DDoS: Overwhelming a system with traffic.

Zero-Day: Exploiting a vulnerability before a patch exists.

6. Virus vs. Worm
Virus: Requires a host file and human action (like opening an attachment) to spread and execute.

Worm: A self-replicating program that spreads across networks automatically without human intervention.

7. Social Engineering
Often called "human hacking," it is the psychological manipulation of people into performing actions or divulging confidential information (e.g., baiting, pretexting, or phishing).

8. Key Components of an Information Security Program
Security Leadership: (e.g., a CISO).

Policies and Standards: The "rules" of the organization.

Risk Assessment: Identifying what needs protection.

Incident Response: Plans for when a breach occurs.

Awareness Training: Educating employees.

9. Policies and Frameworks (NIST, ISO)
Frameworks (like the NIST CSF) provide a structured roadmap. They help organizations move from a reactive "firefighting" state to a proactive, mature security posture by defining how to Identify, Protect, Detect, Respond, and Recover.

10. The Purpose of the OWASP Top Ten
The OWASP Top Ten is a standard awareness document for developers and web security professionals. It represents a broad consensus on the most critical security risks to web applications, such as Broken Access Control and Injection.

11. The Role of Access Control
Access control ensures that users are who they say they are (Authentication) and that they only have access to the specific resources they need to do their job (Authorization / Principle of Least Privilege).

12. Multi-Factor Authentication (MFA)
MFA enhances security by requiring two or more independent credentials for access.

Something you know: (Password).

Something you have: (Security token or phone).

Something you are: (Biometrics/Fingerprint).

13. Common Methods for Securing a Network
Firewalls: Filtering incoming/outgoing traffic.

VPNs: Creating secure, encrypted "tunnels" over the internet.

Intrusion Detection Systems (IDS): Monitoring for suspicious activity.

Network Segmentation: Dividing a network into smaller parts to contain potential breaches.

--------------------------------------------------------------------------------

Tasks

0. Did you install kali ?

In Kali Linux, the standard way to retrieve the Distributor ID specifically is using the lsb_release command.

The Script (0-release.sh)
Bash
#!/bin/bash
lsb_release -is

Why this works:
lsb_release: This is the standard utility for querying Linux distribution information.

-i: Stands for "id" (Distributor ID).
-s: Stands for "short" (displays only the value without the label "Distributor ID:").

Constraint Check: It is a single command, avoids awk, avoids printf, and handles the output exactly as required by the example.


1. We always need strong Passwords

The Script (1-gen_password.sh)
Bash
#!/bin/bash
tr -dc '[:alnum:]' < /dev/urandom | head -c $1

Logic Breakdown
tr -dc '[:alnum:]':

tr is the "translate" or "delete" command.

The -d flag means delete.

The -c flag means complement (everything except the specified characters).

'[:alnum:]' is the character class for alphanumeric characters (A-Z, a-z, 0-9).

Result: This command tells the system: "Delete everything that is NOT a letter or a number."

< /dev/urandom:

/dev/urandom is a special file in Linux that serves as a cryptographically secure random number generator.

The < symbol redirects the stream of random data into the tr command.

| head -c $1:

The pipe (|) takes the cleaned-up stream of random letters and numbers and sends it to head.

head -c tells the script to take exactly a certain number of bytes (characters).

$1 is the variable representing the first argument you pass to the script (e.g., if you run ./script.sh 15, $1 becomes 15).


2. Verify the integrity of a file

The Script (2-sha256_validator.sh)
Bash
#!/bin/bash
echo "$2 $1" | sha256sum -c

Logic Breakdown
The Arguments ($1 and $2):

$1: This represents the filename (e.g., test_file).

$2: This represents the SHA256 hash string provided to you.

echo "$2 $1":

The sha256sum -c command expects input in a specific format: HASH FILENAME.

By using echo, we arrange the hash and the filename exactly how the tool needs to see them.

The Pipe (|):

This takes the text we just prepared with echo and "feeds" it directly into the input of the next command.

sha256sum -c:

sha256sum is the utility used to calculate or verify SHA256 hashes.

The -c flag stands for check. It tells the program: "Read the provided hash and compare it against the actual content of the file on the disk."

If they match, it prints OK. If they don't, it prints FAILED.

Significance in Cybersecurity
This script is a direct implementation of Integrity (the "I" in the CIA Triad).

In the real world, cybersecurity professionals use this method to ensure that a file hasn't been tampered with by a hacker or corrupted during a download. Even a tiny change in the file (like adding a single space) will result in a completely different hash.


3. We need an SSH key pair!

The Script (3-gen_key.sh)
Bash
#!/bin/bash
ssh-keygen -b 4096 -t rsa -f "$1" -N ""

Logic Breakdown
ssh-keygen: The standard OpenSSH tool for creating new authentication key pairs.

-b 4096: Specifies the number of bits in the key. 4096 is significantly more secure than the default 2048.

-t rsa: Specifies the type of key to create (RSA).

-f "$1": Specifies the filename for the key file. It uses the first argument you provide when running the script.

-N "": This is a crucial flag for automation. It sets the passphrase to "empty," so the script won't pause and ask you to type a password.

Why we need an SSH Key Pair?
In cybersecurity, SSH keys are used for Identity and Access Management (IAM).

Private Key (e.g., new_key): Like a physical key. You keep it on your machine and never share it.

Public Key (e.g., new_key.pub): Like a lock. You place it on the server you want to access. This provides much stronger security than traditional passwords because it is nearly impossible to "brute-force" a 4096-bit RSA key.


4. Let's Monitor root activity

The Script (4-root_process.sh)
Bash
#!/bin/bash
ps -u "$1" -f | grep -v "0      0"

Logic Breakdown
ps -u "$1" -f:

ps: The standard utility for reporting a snapshot of current processes.

-u "$1": Filters processes by User. It uses the first argument you provide (like root). In Python terms, this is sys.argv[1].

-f: Stands for Full-format. This adds essential columns like the UID (User ID), PID (Process ID), and the full command path, which are vital for security auditing.

The Pipe (|):

Takes the massive list of processes and "streams" it into the filter command.

grep -v "0 0":

grep: A tool used to search for text patterns.

-v: This flag stands for Invert-match. Instead of showing lines that match, it hides them.

"0 0": We are looking for lines where the memory columns (VSZ and RSS) are both zero.

Why this is important for Cybersecurity
In Linux, processes with 0 VSZ (Virtual Memory Size) and 0 RSS (Resident Set Size) are usually Kernel Threads.

While these are necessary for the operating system to function, a security analyst monitoring "Root Activity" is usually looking for User-space processes (like backdoors, unauthorized shells, or malicious scripts). By filtering out the kernel threads, you clear the "noise" and focus only on actual programs being executed.
