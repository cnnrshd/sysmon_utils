#!/bin/bash
# Find all "status.json" files
find . -type f -name "status.json" -print0 |

# Use xargs to print the contents of these files
xargs -0 cat |

# Filter for Successful Tests & create a custom object with FilePath
jq -s '
    .[] | 
    select(.Status | test("Successful")) | 
    {
        "Status" : .Status, 
        "Technique" : .Technique, 
        "TestNumber" : .TestNumber, 
        "FilePath" : "./\(.Technique)/\(.TestNumber)"
    }' > successful_tests.json  # Output the result to "successful_tests.json"
