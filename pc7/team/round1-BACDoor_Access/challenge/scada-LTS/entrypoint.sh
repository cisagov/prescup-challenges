#!/bin/bash

TOKEN_FILE=/usr/local/tomcat/webapps/Scada-LTS/assets/dFld0XeCe7pe3z.html

# Prepare the configs with our new IP addresses

python3 /ip_replacement.py 

# Give devices extra time just in case
echo "Sleeping to wait for BACnet devices..."
sleep 10

# Wait for database per Scada-LTS docs
/usr/bin/wait-for-it --host=database --port=3306 --timeout=60 --strict

/usr/local/tomcat/bin/catalina.sh run &
TOMCAT_PID=$!

# Wait for SCADA-LTS to become ready
echo "Waiting for SCADA-LTS to initialize..."
until curl -s http://localhost:8080/Scada-LTS/login.htm >/dev/null; do
  sleep 5
done

curl -d "username=admin&password=admin&submit=Login" -c /cookies http://localhost:8080/Scada-LTS/login.htm
curl -b /cookies  -v -F importFile=@/export.zip http://localhost:8080/Scada-LTS/import_project.htm
curl 'http://localhost:8080/Scada-LTS/dwr/call/plaincall/EmportDwr.loadProject.dwr' -X POST -b /cookies --data-raw $'callCount=1\npage=/Scada-LTS/import_project.htm\nhttpSessionId=\nscriptSessionId=D15BC242A0E69D4251D5585A07806324697\nc0-scriptName=EmportDwr\nc0-methodName=loadProject\nc0-id=0\nbatchId=5\n'

sleep 60  # Need to wait for import

echo "<span style='color:limegreen; font-weight:bold'>${tokenHMI}</span>" > "$TOKEN_FILE"

RESPONSE=$(curl -s 'http://localhost:8080/Scada-LTS/api/auth/MLin2/password123')

if [[ "$RESPONSE" == "true" ]]; then
  echo "Import appears successful"
else
  echo "ERROR!!! Import appears to have failed."
fi

wait $TOMCAT_PID