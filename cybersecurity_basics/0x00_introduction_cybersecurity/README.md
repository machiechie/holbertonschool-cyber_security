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
