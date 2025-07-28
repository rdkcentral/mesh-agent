#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

if [ -f /etc/device.properties ]; then
    source /etc/device.properties
fi

source /lib/rdk/getpartnerid.sh

RDK_LOGGER_PATH="/rdklogger"
NVRAM2_SUPPORTED="no"
. /lib/rdk/utils.sh
. $RDK_LOGGER_PATH/logfiles.sh
UPLOAD_LOGS='false'
UPTIME=`uptime`
upload_protocol='HTTP'
upload_httplink='None'
DIRECT_MAX_ATTEMPTS=3
URLENCODE_STRING=""
S3_URL=""
OutputFile='/tmp/recorderhttpresult.txt'
mwo_defaults_path='/usr/ccsp/meshwifioptimizer/MWO_Defaults'
recording_stale_threshold=0
loop=1

if [ -f /lib/rdk/exec_curl_mtls.sh ]
then
   source /lib/rdk/exec_curl_mtls.sh
fi

recorder_cleanup()
{
    cd $UploadDir
    rec_stale_threshold_in_min=$((recording_stale_threshold / 60))
    find . -type f -name "*mworec" -mmin +$rec_stale_threshold_in_min -exec rm -f {} \;
    if [ $? -eq 0 ]; then
        echo_t "HCM: Removed mworec files older than $((rec_stale_threshold_in_min / 60)) hours"
    else
        echo_t "HCM: Failed to remove mworec files older than $((rec_stale_threshold_in_min / 60)) hours"
    fi
    is_mesh_enabled=`syscfg get mesh_enable`
    is_recorder_enabled=`syscfg get recorder_enable`
    hcm_mode=`syscfg get mesh_optimized_mode`
    if [ "$is_mesh_enabled" = "true" ] || [ "$is_recorder_enabled" = "false" ] || [ "$hcm_mode" -eq 0 ]; then
        #clean up the artifacts
        if [ -d "$UploadDir/general" ];
        then
            cd "$UploadDir/general"
            find . -type f -name "*" -mmin +$rec_stale_threshold_in_min -exec rm -f {} \;
        fi
	if [ -d "$UploadDir/timeline" ];
        then
            cd "$UploadDir/timeline"
            find . -type f -name "*" -mmin +$rec_stale_threshold_in_min -exec rm -f {} \;
        fi
        echo_t "HCM: HCM is disabled or in reserve mode, removing artifacts from $UploadDir"
        return
    fi
}

UseDirectUpload()
{
    # Direct Communication
    # Performing DIRECT_MAX_ATTEMPTS tries for successful curl command execution.
    # $http_code --> Response code retrieved from HTTP_CODE file path.

        retries=0
        while [ "$retries" -lt "$DIRECT_MAX_ATTEMPTS" ]
        do
            echo_t "HCM: Trying Direct Communication"
            WAN_INTERFACE=$(getWanInterfaceName)
            echo_t "HCM: Trial $retries for DIRECT ..."
            msg_tls_source="TLS"
            CURL_ARGS="--tlsv1.2 -w '%{http_code}\n' -d \"filename=$UploadFile\" $URLENCODE_STRING -o \"$OutputFile\" --interface $WAN_INTERFACE $addr_type \"$S3_URL\" $CERT_STATUS --connect-timeout 30 -m 30"
            if [[ ! -e $UploadFile ]]; then
                echo_t "HCM: No file exist or already uploaded!!!"
                http_code=-1
                break;
            fi
            FQDN=`echo "$S3_URL" | awk -F/ '{print $3}'`
            if [ -f /lib/rdk/exec_curl_mtls.sh ]
            then
                ret=` exec_curl_mtls "$CURL_ARGS" "HCMRecordingUL" "$FQDN"`
            else
                echo_t "HCM: exec_curl_mtls is not available."
                break
            fi
            if [ -f $HTTP_CODE ] ; then
               http_code=$(awk '{print $1}' $HTTP_CODE)
               if [ "$http_code" != "" ];then
                   echo_t "HCM: Recorder Upload: $msg_tls_source Direct Communication - ret:$ret, http_code:$http_code"
                   if [ "$http_code" = "200" ] || [ "$http_code" = "302" ] ;then
                        return 0
                   fi
               fi
            else
               http_code=0
               echo_t "HCM: Recorder Upload: $msg_tls_source Direct Communication Failure Attempt:$retries - ret:$ret, http_code:$http_code"
            fi
            retries=`expr $retries + 1`
            sleep 60
        done
        echo_t "HCM: Retries for Direct connection exceeded "
    return 1
}

UploadToAmazonS3()
{
    Key=$(awk -F\" '{print $0}' $OutputFile)
    if [ -z "$Key" ]; then
        echo_t "HCM: Key is empty, cannot upload to S3"
        return 1
    fi
    echo "$Key" | tr '[:upper:]' '[:lower:]' | grep -q -e 'http://'
    if [ "$?" = "0" ]; then
        echo_t "HCM: RECORDER UPLOAD TO S3 requested http. Forcing to https"
        Key=$(echo "$Key" | sed -e 's#http://#https://#g' -e 's#:80/#:443/#')
        forced_https="true"
    else
        forced_https="false"
    fi
    RemSignature=`echo $Key | sed "s/AWSAccessKeyId=.*Signature=.*&//g;s/\"//g;s/.*https/https/g"`
    if [ "$encryptionEnable" != "true" ]; then
        Key=\"$Key\"
    fi
    echo_t "HCM: Generated KeyIs : "
    echo $RemSignature
    CURL_CMD="nice -n 20 curl --tlsv1.2 -w '%{http_code}\n' -T $UploadFile -o \"$OutputFile\" --interface $WAN_INTERFACE $Key $CERT_STATUS --connect-timeout 30 -m 30"
    # Sensitive info like Authorization signature should not print
    CURL_CMD_FOR_ECHO="nice -n 20 curl --tlsv1.2 -w '%{http_code}\n' -T $UploadFile -o \"$OutputFile\" --interface $WAN_INTERFACE \"$RemSignature\" $CERT_STATUS --connect-timeout 30 -m 30"

    retries=0
    while [ "$retries" -lt "3" ]
    do
        WAN_INTERFACE=$(getWanInterfaceName)
        echo_t "HCM: Trial $retries..."
        # nice value can be normal as the first trial failed
        if [ $retries -ne 0 ]; then
            CURL_CMD="curl --tlsv1.2 -w '%{http_code}\n' -T $UploadFile -o \"$OutputFile\" --interface $WAN_INTERFACE $Key $CERT_STATUS --connect-timeout 30 -m 30"
            # Sensitive info like Authorization signature should not print
            CURL_CMD_FOR_ECHO="curl --tlsv1.2 -w '%{http_code}\n' -T $UploadFile -o \"$OutputFile\" --interface $WAN_INTERFACE \"$RemSignature\" $CERT_STATUS --connect-timeout 30 -m 30"
        fi
            if [[ ! -e $UploadFile ]]; then
            echo_t "HCM: No file exist or already uploaded!!!"
            http_code=-1
            break
        fi
        #Sensitive info like Authorization signature should not print
        echo_t "HCM: Curl Command built: $CURL_CMD_FOR_ECHO"
        eval $CURL_CMD > $HTTP_CODE
        ret=$?

        #Check for forced https security failure
        if [ "$forced_https" = "true" ]; then
            case $ret in
                35|51|53|54|58|59|60|64|66|77|80|82|83|90|91)
                echo_t "HCM: RECORDER UPLOAD TO S3 forced https failed"
            esac
        fi

        if [ -f $HTTP_CODE ]; then
            http_code=$(awk '{print $0}' $HTTP_CODE)

            if [ "$http_code" != "" ];then
                echo_t "HCM: HttpCode received is : $http_code"
                if [ "$http_code" = "200" ];then
                    break
                fi
            fi
        else
            http_code=0
        fi

        retries=`expr $retries + 1`
        sleep 30
    done

    # Response after executing curl with the public key is 200, then file uploaded successfully.
    if [ "$http_code" = "200" ];then
        echo_t "HCM: RECORDER UPLOADED SUCCESSFULLY"
    fi
}

HttpRecorderUpload()
{
    UPLOAD_LOGS=`syscfg get hcm_recording_upload_enable`
    if [ "$UPLOAD_LOGS" = "true" ];
    then
        if [ -d "$UploadDir" ];
        then
            cd $UploadDir
        else
            echo_t "HCM: Directory was not found : $UploadDir"
	    exit 1
        fi
        FILE_NAME=`ls | grep "mworec"`
        if [ ! -z "$FILE_NAME" ];
        then
            if [ -f '/tmp/DCMresponse.txt' ];
            then
                S3_URL=`grep 'HCMRecorderSettings:UploadRepository:URL' /tmp/DCMresponse.txt`
            fi
            if [ -z "$S3_URL" ];
            then 
                echo_t "HCM: Couldn't able to get URL from DCM response, Using the default URL for upload"
                S3_URL=`dmcli eRT retv Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.HCMRecordingUploadURL`
            fi

            random_number=$((1 + RANDOM % 3601)) # Random number between 1 and 3600 seconds (1 hour)
            echo_t "HCM: Putting the process to sleep for a random duration of $random_number seconds"
            sleep $random_number
            echo_t "HCM: files to be uploaded is : $FILE_NAME"
            file_list=$FILE_NAME
            for UploadFile in $file_list
            do
                echo_t "HCM: Upload directory is : $UploadDir"
                echo_t "HCM: Upload file is : $UploadFile"
                echo_t "HCM: System Uptime is $UPTIME"
                echo_t "HCM: S3 URL is : $S3_URL"
                UseDirectUpload
                ret=$?
                if [ "$ret" -ne "0" ] && [ "$http_code" -ne "-1" ]; then
                    echo_t "HCM: INVALID RETURN CODE: $http_code"
                    echo_t "HCM: Could not fetch HCM Recording upload S3 URL."
                    continue
                fi
 
                if [ "$http_code" = "200" ];then
                    UploadToAmazonS3
                    ret=$?
                    if [ "$ret" -ne "0" ]; then
                        echo_t "HCM: HCM RECORDING FILE UPLOAD UNSUCCESSFUL TO S3"
                    else
                        echo_t "HCM: HCM RECORDING FILE UPLOADED SUCCESSFULLY TO S3"
                        rm -f $UploadFile
                    fi
                else
                    echo_t "HCM: Could not fetch HCM Recording upload S3 URL."
                fi
            done
        else
            echo_t "HCM: No files to upload"
        fi
    fi
    rm -f $OutputFile
}

main() 
{
    echo_t "HCM: Starting HCM recording upload script"
    UploadDir=$( awk '/"RE": *\{/,/}/' "$mwo_defaults_path" | grep '"dump_path"' | sed 's/.*: *"\([^"]*\)".*/\1/')
    recording_stale_threshold=$(awk '/"recorder": *\{/,/}/' "$mwo_defaults_path" | grep -Eo '"recording_stale_threshold"[[:space:]]*:[[:space:]]*[0-9]+' | grep -Eo '[0-9]+')
    #Adding a 24-hour buffer to the recording_stale_threshold to prevent unnecessary deletions.
    recording_stale_threshold=$((recording_stale_threshold + 86400))
    HttpRecorderUpload
    echo_t "HCM: clean mworec files if any"
    recorder_cleanup
    echo_t "HCM: Exiting HCM recording upload script"
    exit 0
}

main
