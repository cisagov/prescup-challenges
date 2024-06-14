
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os
import random
import json

# Function to generate random GPS coordinates within CONUS
def generate_random_gps_coordinate():
    # CONUS boundary coordinates (latitude and longitude)
    min_latitude = 24.396308
    max_latitude = 49.345786
    min_longitude = -125.000000
    max_longitude = -66.934570

    # Generate random latitude and longitude within CONUS boundaries
    latitude = random.uniform(min_latitude, max_latitude)
    longitude = random.uniform(min_longitude, max_longitude)

    return latitude, longitude

# Number of agents and targets
num_agents = 1776
num_targets = 100

# Create directories to store agent and target data
if not os.path.exists("agents"):
    os.makedirs("agents")
if not os.path.exists("targets"):
    os.makedirs("targets")

# Generate data for agents
for agent_id in range(1, num_agents + 1):
    agent_name = f"Agent{agent_id:04}"
    latitude, longitude = generate_random_gps_coordinate()
    
    agent_info = {
        "AgentID": agent_id,
        "Name": agent_name,
        "LastKnownLocation": {
            "Latitude": latitude,
            "Longitude": longitude
        }
    }

    # Save agent data as JSON in the 'agents' directory
    agent_filename = os.path.join("agents", f"{agent_name}.json")
    with open(agent_filename, "w") as agent_file:
        json.dump(agent_info, agent_file, indent=4)

print(f"{num_agents} agent data files saved in the 'agents' directory.")

# Generate data for targets
for target_id in range(1, num_targets + 1):
    target_name = f"Target{target_id:03}"
    latitude, longitude = generate_random_gps_coordinate()
    
    target_info = {
        "TargetID": target_id,
        "Name": target_name,
        "LastKnownLocation": {
            "Latitude": latitude,
            "Longitude": longitude
        }
    }

    # Save target data as JSON in the 'targets' directory
    target_filename = os.path.join("targets", f"{target_name}.json")
    with open(target_filename, "w") as target_file:
        json.dump(target_info, target_file, indent=4)

print(f"{num_targets} target data files saved in the 'targets' directory.")

