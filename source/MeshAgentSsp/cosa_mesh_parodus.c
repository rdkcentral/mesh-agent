/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2018 RDK Management
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _RDKB_MESH_AGENT_C_
#define _RDKB_MESH_AGENT_C_

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include "stdbool.h"
#include <pthread.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <fcntl.h>

#include "cosa_mesh_parodus.h"
#include <libparodus/libparodus.h>
#include <cjson/cJSON.h>
#include <math.h>
#include "ansc_platform.h"
#include "meshsync_msgs.h"
//#include "ccsp_trace.h"
#include "cosa_apis_util.h"
#include "cosa_meshagent_internal.h"
#include "meshagent.h"
#include "mesh_client_table.h"
#include "ssp_global.h"
#include "cosa_webconfig_api.h"
#include "safec_lib_common.h"

// TELEMETRY 2.0 //RDKB-26019
#include <telemetry_busmessage_sender.h>

libpd_instance_t mesh_agent_instance;
static char deviceMAC[32] = {'\0'};

typedef struct _notify_params
{
    pod_event_id evt_id;
    pod_event_type evt_type;
    char mac[MAX_MAC_ADDR_LEN];
} notify_params_t;

typedef struct _mesh_event_notify
{
    int evt_id;
    char *event_string;
} mesh_event_notify_t;

mesh_event_notify_t mesh_event[] =
{
    {EB_RFC_DISABLED,   "EB_RFC_DISABLE"},
    {EB_XHS_PORT,       "EB_XHS_PORT"},
    {EB_GENERIC_ISSUE,  "EB_GENERIC_ISSUE"},
};

#define MAX_PARAMETERNAME_LEN       512
#define DEVICE_MAC                  "Device.X_CISCO_COM_CableModem.MACAddress"
#define DEVICE_PROPS_FILE           "/etc/device.properties"
#define CONTENT_TYPE_JSON           "application/json"
#define DEVINFO_CMD_FMT             "/usr/sbin/deviceinfo.sh -%s"
#define DEVINFO_MAX_LEN             32
#define DEVINFO_CMD_MAX             DEVINFO_MAX_LEN + 32
#define DEVINFO_CM_MAC              "cmac"


static void get_parodus_url(char **url);
void sendNotification(notify_params_t* param);
static void get_parodus_url(char **url);
const char *rdk_logger_module_fetch(void);

static void get_parodus_url(char **url)
{
    FILE *fp = fopen(DEVICE_PROPS_FILE, "r");

    if( NULL != fp ) {
        char str[255] = {'\0'};
        /*CID 135653  Calling risky function */
        while( fscanf(fp,"%254s", str) != EOF) {
            char *value = NULL;
            if( ( value = strstr(str, "PARODUS_URL=") ) ) {
                value = value + strlen("PARODUS_URL=");
                *url = strdup(value);
                MeshInfo("parodus url is %s\n", *url);
            }
        }
        fclose(fp);
    } else {
        MeshError("Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE);
    }

    if( NULL == *url ) {
        MeshError("parodus url is not present in device.properties file\n");
    }

    MeshInfo("parodus url formed is %s\n", *url);
}

bool parodusInit()
{
    char * parodus_url = NULL;
    get_parodus_url(&parodus_url);
    libpd_cfg_t cfg = { .service_name = "mesh_agent",
                        .receive = false,
                        .keepalive_timeout_secs = 0,
                        .parodus_url = parodus_url,
                        .client_url = NULL
                      };
    
    int ret = libparodus_init(&mesh_agent_instance, &cfg);
    if(ret != 0) {
        MeshError("Failed to initialize parodus\n");
        libparodus_shutdown(&mesh_agent_instance);
        return false;
    }

    return true;
}

bool devinfo_getv(const char *what, char *dest, size_t destsz, bool empty_ok)
{
    char        cmd[DEVINFO_CMD_MAX];
    FILE        *f1;
    int         ret;

    if (strlen(what) > DEVINFO_MAX_LEN) {
        MeshError("devinfo_getv(%s) - Item too long, %d bytes max", what, DEVINFO_MAX_LEN);
        return false;
    }

    ret = snprintf(cmd, sizeof(cmd)-1, DEVINFO_CMD_FMT, what);
    if (ret >= (int)(sizeof(cmd)-1)) {
        MeshError("devinfo_getv(%s) - Command too long!", what);
        return false;
    }

    f1 = popen(cmd, "r");
    if (!f1) {
        MeshError("devinfo_getv(%s) - popen failed, errno = %d", what, errno);
        return false;
    }

    if (fgets(dest, destsz, f1) == NULL) {
        MeshError("devinfo_getv(%s) - reading failed, errno = %d", what, errno);
        pclose(f1);
        return false;
    }
    pclose(f1);

    while(dest[strlen(dest)-1] == '\r' || dest[strlen(dest)-1] == '\n') {
        dest[strlen(dest)-1] = '\0';
    }

    if (!empty_ok && strlen(dest) == 0) {
        return false;
    }

    return true;
}

bool notifyEvent(pod_event_type evt_type, pod_event_id evt_id, const char * pod_mac)
{
    cJSON *notifyPayload = NULL;
    char  * stringifiedNotifyPayload = NULL;
    wrp_msg_t notify_wrp_msg = { 0 };
    char cmmac[32];
    char dest[1024] = {'\0'};

    if(pod_mac == NULL) {
        MeshError("Calling notifyEvent() with NULL pod_mac\n");
        return false;
    }

    if(strlen(deviceMAC) == 0)
    {
        /* TODO: add lock as multiple thread might keep on get the cmac */
        if (!devinfo_getv(DEVINFO_CM_MAC, cmmac, sizeof(cmmac), false))
        {
            MeshError("Failed to get the deviceMAC \n");
            return false;
        }

        AnscMacToLower(deviceMAC, cmmac, sizeof(deviceMAC));
    }

    MeshInfo("deviceMAC is %s\n",deviceMAC);

    if(strlen(deviceMAC) == 0)
    {
        MeshError("deviceMAC is NULL, failed to send Notification\n");
        return false;
    }

    notifyPayload = cJSON_CreateObject();
    if(notifyPayload == NULL) {
        MeshError("Failed to create notifyPayload JSON object.\n");
        return false;
    }

    cJSON_AddStringToObject(notifyPayload,"device_id", deviceMAC);
    cJSON_AddStringToObject(notifyPayload,"pod_id", pod_mac);

    if (evt_type == ERROR)
    {
        cJSON_AddStringToObject(notifyPayload,"event_type", "ERROR");
    }
    else if (evt_type == INFO)
    {
        cJSON_AddStringToObject(notifyPayload,"event_type", "INFO");
    }

    char evt_id_str[2] = { 0 };
    evt_id_str[0] = evt_id + '0';
    cJSON_AddStringToObject(notifyPayload,"event_id", evt_id_str);
    cJSON_AddStringToObject(notifyPayload,"event_msg", mesh_event[evt_id].event_string);

    stringifiedNotifyPayload = cJSON_PrintUnformatted(notifyPayload);
    MeshInfo("Notification payload %s\n",stringifiedNotifyPayload);
    cJSON_Delete(notifyPayload);

    notify_wrp_msg.msg_type = WRP_MSG_TYPE__EVENT;
    notify_wrp_msg.u.event.source = deviceMAC;

    snprintf(dest,sizeof(dest),"event:mesh-agent/mac:%s/%s/%s/%d/%s",
                    deviceMAC, (evt_type == ERROR ? "ERROR" : "INFO"), pod_mac, evt_id, mesh_event[evt_id].event_string);
    notify_wrp_msg.u.event.dest = dest;
    notify_wrp_msg.u.event.content_type = CONTENT_TYPE_JSON;
    if(stringifiedNotifyPayload != NULL)
    {
        notify_wrp_msg.u.event.payload = (void *) stringifiedNotifyPayload;
        notify_wrp_msg.u.event.payload_size = strlen(stringifiedNotifyPayload);
    }

    int ret = libparodus_send(mesh_agent_instance, &notify_wrp_msg );
    if(ret != 0)
    {
        MeshError("Failed to send notification to parodus\n");
        return false;
    }

    MeshInfo("Parodus send was successful!\n");
    return true;
}

const char *rdk_logger_module_fetch(void)
{
    return "LOG.RDK.MESHAGENT";
}

#endif
