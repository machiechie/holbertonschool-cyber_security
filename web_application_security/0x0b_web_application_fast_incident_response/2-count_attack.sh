#!/bin/bash
# Identify the top attacker IP and count their total requests

awk '{print $1}' logs.txt | sort | uniq -c | sort -nr | head -1 | awk '{print $1}'
