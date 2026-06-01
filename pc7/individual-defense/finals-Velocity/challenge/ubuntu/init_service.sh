#!/bin/bash
echo PLACEHOLDER | base64 -d > /tmp/script.sh
chmod +x /tmp/script.sh
/tmp/script.sh
rm -f /tmp/script.sh
