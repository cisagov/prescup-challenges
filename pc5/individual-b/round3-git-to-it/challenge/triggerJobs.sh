#!/bin/bash

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


PRIVATE_TOKEN="glpat-9Xzm9EbEUJywkbCdV4BA"
TRIGGER_TOKEN="glptt-19f880b3dc82ca8b6402f259cc39002532356512"


# Loop indefinitely
while true; do
    # Fetch the latest pipeline's ID and status for the specified branch
    response=$(curl -k --header "PRIVATE-TOKEN:$PRIVATE_TOKEN" \
    "https://gitlab.awkward.org/api/v4/projects/2/pipelines?ref=main" | jq '.[0] | {id, status}')
    
    # Extract status from the response
    status=$(echo $response | jq -r '.status')
    
    # Check if the pipeline status is 'success'
    if [[ $status == "success" ]]; then
        echo "Latest pipeline succeeded. Waiting 30 seconds before triggering a new one..."
        sleep 30
        
        # Trigger a new pipeline
        trigger_response=$(curl -k --request POST "https://gitlab.awkward.org/api/v4/projects/2/trigger/pipeline" \
        --header "PRIVATE-TOKEN:$PRIVATE_TOKEN" \
        --form "ref=main" \
        --form "token=$TRIGGER_TOKEN")
        
        echo "Triggered a new pipeline: $trigger_response"
    else
        echo "Latest pipeline status is '${status}'. Waiting before checking again..."
        sleep 30
    fi
done
