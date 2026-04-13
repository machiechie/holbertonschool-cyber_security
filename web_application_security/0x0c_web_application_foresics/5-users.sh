#!/bin/bash
grep "new user" auth.log | awk -F'[,=]' '{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//'
