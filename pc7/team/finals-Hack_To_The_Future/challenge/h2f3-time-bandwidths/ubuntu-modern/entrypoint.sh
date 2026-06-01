#!/bin/bash
cd /time-bandwidths/
/time-bandwidths/server &
/usr/sbin/sshd -D
