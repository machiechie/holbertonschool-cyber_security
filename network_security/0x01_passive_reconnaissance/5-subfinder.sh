#!/bin/bash
subfinder -d $1 -silent -o $1.txt -ip -oJ | awk -F'[:,]' '{print $2","$4}'
