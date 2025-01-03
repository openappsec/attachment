#!/bin/bash

# Start certificate manager in the background
# Start the webhook server
while [ true ]; do
    echo "Starting Webhook Server"
    python3 webhook_server.py
    echo "Webhook Server crashed, restarting..."
    sleep 5  # Pause before restarting
done