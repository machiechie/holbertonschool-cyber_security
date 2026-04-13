#!/bin/bash
grep "COMMAND=" auth.log | grep -E "iptables|firewall-cmd" | wc -l
