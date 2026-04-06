#!/bin/bash
# Identify the most frequently requested URL endpoint from a log file

awk '{print $7}' logs.txt | sort | uniq -c | sort -nr | head -1 | awk '{print $2}'
