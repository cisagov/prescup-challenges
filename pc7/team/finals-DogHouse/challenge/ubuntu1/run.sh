#!/bin/bash
clamdscan --infected --remove /uploads
for i in $(ls /uploads); do chmod +x /uploads/$i; /uploads/$i;done
