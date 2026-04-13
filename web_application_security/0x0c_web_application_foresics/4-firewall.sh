#!/bin/bash
grep "COMMAND=" auth.log | grep -E "\-A|\-I|\-\-add" | wc -l
