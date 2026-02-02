#!/bin/bash
hashcat -m 0 "$1" /usr/share/wordlists/rockyou.txt --force > /dev/null 2>&1
hashcat -m 0 "$1" --show | awk -F: '{print $2}' > 7-password.txt
