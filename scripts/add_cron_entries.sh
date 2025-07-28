#! /bin/sh
if [ -f /etc/device.properties ]
then
    source /etc/device.properties
fi
CRONFILE=$CRON_SPOOL"/root"
CRONFILE_BK="/tmp/cron_tab$$.txt"
ENTRY_ADDED=0
echo "Start Channel Keepout Setup"
if [ -f $CRONFILE ]
then
    # Dump existing cron jobs to a file & add new job
    crontab -l -c $CRON_SPOOL > $CRONFILE_BK
    # Check whether specific cron jobs are existing or not
    existing_channel_keepout=$(grep "run_channel_keepout.sh" $CRONFILE_BK)
    if [ -z "$existing_channel_keepout" ]; then
        echo "0 3 * * * /usr/ccsp/mesh/run_channel_keepout.sh" >> $CRONFILE_BK
        ENTRY_ADDED=1
    fi
    # Check whether HCM recording monitor cron job is existing or not
    existing_hcm_recording=$(grep "rdkbHCMRecordingMonitor.sh" $CRONFILE_BK)
    if [ -z "$existing_hcm_recording" ]; then
        # Add HCM recording monitor cron job
        echo "0 */3 * * * /usr/ccsp/mesh/rdkbHCMRecordingMonitor.sh" >> $CRONFILE_BK
        ENTRY_ADDED=1
    fi
    if [ $ENTRY_ADDED -eq 1 ]; then
        crontab $CRONFILE_BK -c $CRON_SPOOL
    fi
    rm -rf $CRONFILE_BK
else
    echo "$CRONFILE does not exist"
fi
