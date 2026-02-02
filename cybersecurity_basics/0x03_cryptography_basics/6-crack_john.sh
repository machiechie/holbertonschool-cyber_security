#!/bin/bash
john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt "$1" && john --show --format=Raw-SHA256 "$1" | awk -F: 'NR==1{next} {print $2}' | head -n -2 > 6-password.txt
