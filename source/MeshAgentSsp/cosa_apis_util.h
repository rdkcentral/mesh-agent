/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

/*
 * cosa_apis_util.h
 *
 *  Created on: Mar 14, 2017
 */

#ifndef MESHAGENT_SOURCE_MESHAGENT_MESHUTILS_H_
#define MESHAGENT_SOURCE_MESHAGENT_MESHUTILS_H_
#include <stdbool.h>
#include "safec_lib_common.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include "meshsync_msgs.h"

#define      PRI(type)                PRI_ ## type
#define      FMT(type, x)             FMT_ ## type (x)
#define      PRI_os_ipaddr_t          "%d.%d.%d.%d"
#define      FMT_os_ipaddr_t(x)       (x).addr[0], (x).addr[1], (x).addr[2], (x).addr[3]
#define      MAX_IPV4_BYTES           4
#define      GATEWAY_FAILOVER_BRIDGE  "brSTA"
#define      MESH_BHAUL_BRIDGE        "br403"
#define      MESH_XLE_BRIDGE          "br-home"
#define      ETHBACKHAUL0_VLAN        "g-eth0.123"
#define      ETHBACKHAUL1_VLAN        "g-eth1.123"
#define      DEFAULT_MODE             -1
#define      GATEWAY_MODE             0
#define      EXTENDER_MODE            1
#define      TARGET_EXTENDER_TYPE (1 << 1)
#define      TARGET_GW_TYPE       (1 << 0)
#define MAC_SIZE 18
#define MAX_MACS     3

#ifndef RDK_LED_MANAGER_EXIST
typedef enum {
    SOLID = 0,
    BLINKING_SLOW,
    BLINKING_FAST
}eLedAnimation;
typedef enum {
    OFF = 0,
    RED,
    WHITE
}eLedColor;

typedef struct
{
    eLedColor color;           // Enum color
    char         *color_str;   // color str string
}LedColor_Msg;

typedef struct
{
    eLedAnimation animation;       // Enum animation
    char         *animation_str;   // animation_str string
}LedAnimation_Msg;
#endif

#if defined(WAN_FAILOVER_SUPPORTED) || defined(ONEWIFI) || defined(GATEWAY_FAILOVER_SUPPORTED)
typedef struct _MeshStaStatus_node
{
   char sta_ifname[MAX_IFNAME_LEN];
   char bssid[MAX_BSS_ID_STR];
   bool state;
}MeshStaStatus_node;

#endif
typedef struct _MeshDscp
{
    unsigned char mac_addresses[MAX_MACS][MAC_SIZE];
    int dscp_value[MAX_MACS];
}MeshDscp;

typedef struct { unsigned char addr[MAX_IPV4_BYTES]; } os_ipaddr_t;

bool Mesh_SetGreAcc(bool enable, bool init, bool commitSyscfg);
eMeshStateType Mesh_GetMeshState();
void Mesh_SendEthernetMac(char *mac);
bool Mesh_SetOVS(bool enable, bool init, bool commitSyscfg);
bool Mesh_SetSMAPP(bool enable);
bool Recorder_SetEnable(bool enable, bool init, bool commitSyscfg);
bool Mesh_SetMeshEthBhaul(bool enable, bool init, bool commitSyscfg);
bool Mesh_SetXleAdaptiveFh(bool enable);
bool Mesh_SetSecureBackhaul(bool enable);
bool Recorder_UploadEnable(bool enable, bool init, bool commitSyscfg);
bool Mesh_SetXleModeCloudCtrlEnable(bool enable, bool init, bool commitSyscfg);
bool Mesh_SetHDRecommendationEnable(bool enable, bool init, bool commitSyscfg);
void Mesh_SetCacheStatus(bool enable, bool init, bool commitSyscfg);
void Mesh_SetSecuritySchemaLegacy(bool enable, bool init, bool commitSyscfg);
bool Mesh_SetMeshRetryOptimized(bool enable, bool init, bool commitSyscfg);
bool Mesh_SetMeshWifiMotion(bool enable, bool init, bool commitSyscfg);
void Mesh_sendWifiMotionEnable(bool value);
void Mesh_SendEthernetMac(char *mac);
BOOL set_wifi_boolean_enable(char *parameterName, char *parameterValue);
BOOL is_radio_enabled(char *dcs1, char *dcs2);
BOOL is_bridge_mode_enabled();
int getMeshErrorCode();
void* handleMeshEnable(void *Args);
void meshSetSyscfg(bool enable, bool commitSyscfg);
void remove_interface(char *eth_interface, char * eth_wan);

int Mesh_SyseventGetStr(const char *name, unsigned char *out_value, int outbufsz);
int Mesh_SyseventSetStr(const char *name, unsigned char *value, int bufsz, bool toArm);
int Mesh_SysCfgGetInt(const char *name);
int Mesh_SysCfgSetInt(const char *name, int int_value);
int Mesh_SysCfgGetStr(const char *name, unsigned char *out_value, int outbufsz);
int Mesh_SysCfgSetStr(const char *name, unsigned char *str_value, bool toArm);

int svcagt_get_service_state (const char *svc_name);
int svcagt_set_service_state (const char *svc_name, bool state);
int svcagt_set_service_restart (const char *svc_name);
bool Opensync_Set(bool enable, bool init, bool commitSyscfg);

int nif_ifreq(int cmd, char *ifname, struct ifreq *req);
bool get_ipaddr_subnet(char * ifname, char *local_ip, char * remote_ip);
bool nif_netmask_get(char* ifname, os_ipaddr_t* addr);
bool nif_ipaddr_get(char* ifname, os_ipaddr_t* addr);
bool nif_exists(char *ifname, bool *exists);
int  nif_ioctl(int cmd, void *buf);
int handle_uplink_bridge(char *ifname, char * bridge_ip, char *pod_addr, bool create);
bool udhcpc_stop(char* ifname);
bool udhcpc_start(char* ifname);
int udhcpc_pid(char *ifname);
bool ping_ip (char *ip);
#ifndef RDK_LED_MANAGER_EXIST
void  led_state(eLedColor color,eLedAnimation animation);
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
void  handle_led_status(eMeshSyncStatus status, int devicemode);
bool is_eth_connected();
#endif
#endif /* MESHAGENT_SOURCE_MESHAGENT_MESHUTILS_H_ */
