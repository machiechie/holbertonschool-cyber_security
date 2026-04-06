#!/bin/bash
# Identify the User-Agent library used by the top attacker

awk '{print $12}' logs.txt | sort | uniq -c | sort -nr | head -1 | awk '{print $2}'
