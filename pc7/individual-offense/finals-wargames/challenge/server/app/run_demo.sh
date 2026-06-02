#!/bin/sh

# Simply redirects stderr to Docker so we can have some logs
exec /app/demo 2>/tmp/demo_logs
