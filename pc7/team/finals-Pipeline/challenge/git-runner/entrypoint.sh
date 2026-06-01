#!/bin/sh
/tmp/setup.sh
rm /tmp/setup.sh
act_runner --config /home/runner/config.yaml daemon
