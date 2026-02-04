#!/bin/bash
find type -f "$1" -user user2 -exec chown user3 {} +
