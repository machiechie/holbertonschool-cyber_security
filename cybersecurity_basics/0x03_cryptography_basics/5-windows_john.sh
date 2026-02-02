#!/bin/bash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt "$1" && john --show --format=nt "$1" | awk -F: 'NR==1{next} {print $2}' | head -n -2 > 5-password.txt
