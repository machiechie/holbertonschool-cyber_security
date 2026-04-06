#!/bin/bash
# Identify the IP address with the highest number of requests in a log file
# Usage: ./0-attack_ip.sh logs.txt

awk '{print $1}' $1 | sort | uniq -c | sort -nr | head -1 | awk '{print $2}'
