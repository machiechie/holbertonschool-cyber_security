#!/bin/bash
# Identify the User-Agent library used by the top attacker

awk -v attacker=$(awk '{print $1}' logs.txt | sort | uniq -c | sort -nr | head -1 | awk '{print $2}') '$1 == attacker {print $12}' $1 | sort | uniq -c | sort -nr | head -1 | awk '{print $2}'
