#!/bin/bash

echo "🚀 Launching MQTT receiver..."
python mqtt_receiver.py &
mqtt_pid=$!

echo "🌐 Launching dashboard server..."
python dashboard.py &
dash_pid=$!

# Wait for both processes
wait $mqtt_pid
wait $dash_pid
