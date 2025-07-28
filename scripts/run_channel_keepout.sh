#!/bin/bash

LOGFILE="/rdklogs/logs/MeshAgentLog.txt.0"
CHANNELKEEPOUTFILE="/nvram/mesh/channelPlan/channelKeepOut.json"

echo -n "$(date '+%Y-%m-%d %H:%M:%S') " >> $LOGFILE

if [ -s $CHANNELKEEPOUTFILE ]; then
    json_string=$(cat "$CHANNELKEEPOUTFILE")
    echo "TELEMETRY_CHANNEL_PLAN_ENGINE channelKeepOut" >> $LOGFILE
    echo -n "$(date '+%Y-%m-%d %H:%M:%S') " >> $LOGFILE
    plan_id=$(echo "$json_string" | grep -o '"planId":"[^"]*' | sed 's/"planId":"//')
    if [ -z $plan_id ]
    then
        echo "planId is null in the received 6G channel keepout json." >> $LOGFILE
    else
        echo "TELEMETRY_CHANNEL_PLAN_PLANID $plan_id" >> $LOGFILE
    fi
    echo -n "$(date '+%Y-%m-%d %H:%M:%S') " >> $LOGFILE
    channel_exclusion=$(echo "$json_string" | awk -F'"ChannelExclusion":' '{print $2}' | grep -oE '\[.*\]')
    if [ -z $channel_exclusion ]
    then
        echo "channel_exclusion is null in the received 6G channel keepout json." >> $LOGFILE
    else
        echo "TELEMETRY_CHANNEL_PLAN_EXCLUSION_LIST $channel_exclusion" >> $LOGFILE
    fi
else
    echo "File $CHANNELKEEPOUTFILE does not exist or empty" >> $LOGFILE
fi

