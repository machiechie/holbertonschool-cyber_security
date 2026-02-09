#!/bin/bash
sshd -T | grep -Ev '^(#|$)'
