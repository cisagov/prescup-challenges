#!/bin/bash


sshStatus=$(ssh user@target 2>&1 | grep refused | wc -l)

if
    [] $sshStatus -gt 0 ]; then
        service ssh up
fi