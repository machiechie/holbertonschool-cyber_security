#!/bin/bash
# Identify the User-Agent library used by the top attacker

awk -F'"' '{print $6}' logs.txt | sort | uniq -c | sort -nr | head -n 1 | awk '{print $2}'
