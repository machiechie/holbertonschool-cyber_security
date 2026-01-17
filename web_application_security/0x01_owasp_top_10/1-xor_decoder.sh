#!/bin/bash

# Check if the argument is provided
if [ -z "$1" ]; then
    exit 1
fi

# Remove the {xor} prefix if present
encoded_string="${1#\{xor\}}"

# 1. Decode from Base64
# 2. Use 'od' to get decimal values of bytes
# 3. Use 'awk' to XOR each value with 95 and convert back to characters
echo "$encoded_string" | base64 -d | od -v -t u1 -An | awk '{
    for (i=1; i<=NF; i++) 
        printf "%c", bitwise_xor($i, 95)
}
function bitwise_xor(a, b,   r, i, m) {
    r = 0
    m = 1
    for (i=0; i<8; i++) {
        if ((a%2) != (b%2)) r += m
        a = int(a/2)
        b = int(b/2)
        m *= 2
    }
    return r
}
END { print "" }'
