#!/bin/bash
whois | awk -F ": " "/^Registrant |^Admin |^Tech ">$1.csv
