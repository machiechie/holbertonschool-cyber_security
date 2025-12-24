#!/bin/bash
sudo iptables -A INPUT -p tcp -dport 22 -j ACCEPT
