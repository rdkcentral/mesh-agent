#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 start|stop"
    exit 1
fi

action=$1
mac_list="target_macs="

validate_mac() {
    local mac=$1
    if [[ "$mac" =~ ^([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}$ ]]; then
        echo "Valid MAC address: $mac"
    else
        echo "Invalid MAC address: $mac"
    fi
}

if [ $# -eq 0 ]; then
    echo "Usage: $0 <MAC_ADDRESS>"
    exit 1
fi

if [ "$action" == "start" ]; then
     count=$(syscfg get DCPC_PrioClients_Count)

     if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "Error: DCPC_PrioClients_Count is not a valid integer."
        exit 1
    fi

    for ((i=1; i<=count; i++)); do
        mac_key="DCPC_PrioClients_Mac_$i"
        mac_address=$(syscfg get "$mac_key")
        mac_address=$(echo "$mac_address" | tr '[:upper:]' '[:lower:]')
        validate_mac $mac_address
        if [ "$i" -eq "$count" ]; then
            mac_list+="$mac_address"
        else
            mac_list+="$mac_address,"
        fi
        echo "MAC Address at index $i: $mac_address"
    done

    dscp_key="DCPC_PrioClients_DSCP_$count"
    dscp_value=$(syscfg get "$dscp_key")
    mac_list+=" dscp_value=$dscp_value"

    kernel_version=$(uname -r)
    version=$(echo "$kernel_version" | sed -r 's/^([0-9]+\.[0-9]+\.[0-9]+-[^ ]+).*/\1/')
    kernel_module_path="/lib/modules/$version/misc/xmeshgre.ko"

    echo "/sbin/insmod $kernel_module_path $mac_list"
    /sbin/insmod $kernel_module_path $mac_list
elif [ "$action" == "stop" ]; then
    echo "rmmod xmeshgre"
    rmmod xmeshgre
else
    echo "Invalid argument. Please use 'start' or 'stop'."
    exit 1
fi
