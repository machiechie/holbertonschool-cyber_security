#!/bin/bash
# Check for argument
if [ "$#" -ne 1 ]; then
    exit 1
fi

DOMAIN=$1

whois "$DOMAIN" | awk -F': ' '
BEGIN {
    # Define the 12 subfields we need for each group
    split("Name,Organization,Street,City,State/Province,Postal Code,Country,Phone,Phone Ext:,Fax,Fax Ext:,Email", subfields, ",");
    # Define the 3 groups
    split("Registrant,Admin,Tech", groups, ",");
}

# Capture data: Look for lines like "Admin City: Menlo Park"
{
    # Standardize the line by removing "Registry " prefix if it exists
    gsub(/^Registry /, "");
    
    # Check if the line matches our groups
    if ($1 ~ /^(Registrant|Admin|Tech) /) {
        # Store the value ($2) indexed by the label ($1)
        # We trim trailing whitespace from the value
        val = $2;
        sub(/[ \t]+$/, "", val);
        data[$1] = val;
    }
}

END {
    for (i = 1; i <= 3; i++) {
        for (j = 1; j <= 12; j++) {
            group = groups[i];
            subf = subfields[j];
            full_key = group " " subf;
            
            # Handle the "Ext:" fields specifically (they must be empty)
            if (subf ~ /Ext:/) {
                value = "";
            } else {
                value = data[full_key];
            }

            # Requirement: Add a space after Street values if they exist
            if (subf == "Street" && value != "") {
                value = value " ";
            }

            # Requirement: No extra newline at the very end of the file
            if (i == 3 && j == 12) {
                printf "%s,%s", full_key, value;
            } else {
                printf "%s,%s\n", full_key, value;
            }
        }
    }
}' > "${DOMAIN}.csv"
