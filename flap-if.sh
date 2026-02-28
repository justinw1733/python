#!/bin/bash

# Script to flap a network interface based on LACP status
# Usage: ./flap-if.sh [interface_name] [ae_interface]

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Set default values
DEFAULT_INTERFACE="xe-1/2/0"
DEFAULT_AE_INTERFACE="ae0"

# Get interface name from command line argument or prompt user
if [ $# -eq 0 ]; then
    echo "No interface specified"
    read -p "Enter the interface name to flap (e.g., xe-1/2/0): " INTERFACE
    # Use default if empty
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$DEFAULT_INTERFACE
        echo "Using default interface: $INTERFACE"
    fi
    
    read -p "Enter the AE interface name (e.g., ae0): " AE_INTERFACE
    # Use default if empty
    if [ -z "$AE_INTERFACE" ]; then
        AE_INTERFACE=$DEFAULT_AE_INTERFACE
        echo "Using default AE interface: $AE_INTERFACE"
    fi
elif [ $# -eq 1 ]; then
    INTERFACE=$1
    read -p "Enter the AE interface name (e.g., ae0): " AE_INTERFACE
    # Use default if empty
    if [ -z "$AE_INTERFACE" ]; then
        AE_INTERFACE=$DEFAULT_AE_INTERFACE
        echo "Using default AE interface: $AE_INTERFACE"
    fi
else
    INTERFACE=$1
    AE_INTERFACE=$2
fi

echo "Monitoring LACP status for interface: $INTERFACE on $AE_INTERFACE"
echo "Will flap interface when LACP state is Collecting distributing or Distributing"
echo "Will bring interface up when LACP state is Detached"
echo "Press Ctrl+C to stop"
echo "------------------------"

# Counter for flapping cycles
COUNT=0

# Function to handle Ctrl+C interruption
trap 'echo -e "\nInterrupted by user"; echo "Total flapping cycles: $COUNT"; exit 0' SIGINT

# Function to check LACP status
# Returns 0 if collecting/distributing or distributing, 1 if waiting, 3 if detached, 2 if other state/error
check_lacp_status() {
    # Try different methods to execute the Junos command to check LACP status
    OUTPUT=""
    
    # Method 1: Direct cli command
    if command -v cli >/dev/null 2>&1; then
        OUTPUT=$(cli -c "show lacp interfaces $AE_INTERFACE" 2>/dev/null | grep "$INTERFACE" | grep "Current")
    fi
    
    # Method 2: If cli command failed, try with full path
    if [ -z "$OUTPUT" ] && [ -x "/usr/sbin/cli" ]; then
        OUTPUT=$(/usr/sbin/cli -c "show lacp interfaces $AE_INTERFACE" 2>/dev/null | grep "$INTERFACE" | grep "Current")
    fi
    
    # Method 3: Try with sudo if needed
    if [ -z "$OUTPUT" ]; then
        if command -v cli >/dev/null 2>&1; then
            OUTPUT=$(sudo -n cli -c "show lacp interfaces $AE_INTERFACE" 2>/dev/null | grep "$INTERFACE" | grep "Current" 2>/dev/null)
        fi
    fi
    
    # If all methods failed, continue with empty output
    if [ -z "$OUTPUT" ]; then
        return 2
    fi
    
    # Check if the interface is in collecting/distributing or distributing state
    if echo "$OUTPUT" | grep -q "Distributing"; then
        echo "$INTERFACE is in Distributing state"
        return 0
    elif echo "$OUTPUT" | grep -q "Collecting distributing"; then
        echo "$INTERFACE is in Collecting distributing state"
        return 0
    elif echo "$OUTPUT" | grep -q "Detached"; then
        echo "$INTERFACE is in Detached state"
        return 3
    elif echo "$OUTPUT" | grep -q "Waiting"; then
        echo "$INTERFACE is in Waiting state"
        return 1
    else
        echo "$INTERFACE is in another state: $OUTPUT"
        return 2
    fi
}

# Main flapping loop
while true; do
    echo "Checking LACP status..."
    
    # Check interface LACP status
    check_lacp_status
    STATUS=$?
    
    if [ $STATUS -eq 0 ]; then
        # Interface is in distributing or collecting/distributing state - proceed with flapping
        COUNT=$((COUNT + 1))
        echo "Flapping cycle #$COUNT"
        
        # Bring interface down (using the exact command you specified)
        ifconfig $INTERFACE down
        if [ $? -ne 0 ]; then
            echo "Error: Failed to bring interface $INTERFACE down"
            echo "Total flapping cycles: $((COUNT - 1))"
            exit 1
        fi
        
        # Small delay
        sleep 1
        
        # Bring interface up (using the exact command you specified)
        ifconfig $INTERFACE up
        if [ $? -ne 0 ]; then
            echo "Error: Failed to bring interface $INTERFACE up"
            echo "Total flapping cycles: $((COUNT - 1))"
            exit 1
        fi
        
        echo "Interface $INTERFACE flapped successfully"
        sleep 2
    elif [ $STATUS -eq 3 ]; then
        # Interface is in detached state - bring it up
        echo "Interface $INTERFACE is in Detached state, bringing it up..."
        
        # Bring interface up (using the exact command you specified)
        ifconfig $INTERFACE up
        if [ $? -ne 0 ]; then
            echo "Error: Failed to bring interface $INTERFACE up"
            exit 1
        fi
        
        echo "Interface $INTERFACE brought up successfully"
        sleep 2
    elif [ $STATUS -eq 1 ]; then
        # Interface is still in waiting state
        echo "Interface $INTERFACE is in Waiting state, waiting..."
        sleep 1
    else
        # Error or other state - continue monitoring
        echo "Could not retrieve LACP status, continuing to monitor..."
        sleep 2
    fi
done