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

#ifndef _RDKB_MESH_AGENT_C_
#define _RDKB_MESH_AGENT_C_

/*
 * @file cosa_mesh_apis.c
 * @brief Mesh Agent
 *
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/if.h>
#include <string.h>
#include <stdarg.h>
#include "stdbool.h"
#include <pthread.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <fcntl.h>
#ifndef DBUS_SUPPORT
#include <rbus.h>
#include "mesh_rbus.h"
#endif
#include <sys/inotify.h>
#include <cjson/cJSON.h>
#ifdef WAN_FAILOVER_SUPPORTED
#include "ccsp_psm_helper.h"
#include "xmesh_diag.h"
#endif
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
#include "secure_wrapper.h"
#include "ethpod_error_det.h"
#include "cosa_mesh_parodus.h"
#ifdef MESH_OVSAGENT_ENABLE
#include "OvsAgentApi.h"
#endif
#include "helpers.h"
// TELEMETRY 2.0 //RDKB-26019
#include <telemetry_busmessage_sender.h>

extern void initparodusTask();

/**************************************************************************/
/*      LOCAL VARIABLES:                                                  */
/**************************************************************************/
#if defined(ENABLE_MESH_SOCKETS)
/*
 * Unix Domain Sockets
 */
#include <sys/socket.h>
#include <sys/un.h>

#define MAX_CONNECTED_CLIENTS 10  // maximum number of connected clients
const char meshSocketPath[] = MESH_SOCKET_PATH_NAME;
static int clientSockets[MAX_CONNECTED_CLIENTS] = {0};
static int clientSocketsMask = 0;
static int meshError = MB_OK;
#else
/*
 * Message Queues
 */
#include <mqueue.h>

static mqd_t qd_server; // msg queue server handle
const int QUEUE_PERMISSIONS=0660;
const int MAX_MESSAGES=10;  // max number of messages the can be in the queue
#endif

#define ONEWIFI_ENABLED "/etc/onewifi_enabled"
#define WFO_ENABLED     "/etc/WFO_enabled"
#define OPENVSWITCH_LOADED "/sys/module/openvswitch"
#define MESH_ENABLED "/nvram/mesh_enabled"
#define LOCAL_HOST   "127.0.0.1"
#define POD_LINK_SCRIPT "/usr/ccsp/wifi/mesh_status.sh"
#define POD_IP_PREFIX   "192.168.245."
#define XF3_PLATFORM  "XF3"
#define XB3_PLATFORM  "XB3"
#define HUB4_PLATFORM "HUB4"
#define CBR2_PLATFORM "TCCBR"
#define RADIO_ENABLE_24  "Device.WiFi.Radio.1.Enable"
#define RADIO_ENABLE_50  "Device.WiFi.Radio.2.Enable"
#define RADIO_STATUS_24  "Device.WiFi.Radio.1.Status"
#define RADIO_STATUS_50  "Device.WiFi.Radio.2.Status"
#define STATE_DOWN "Down"
#define STATE_FALSE "false"
#define LS_READ_TIMEOUT_MS 2000
#define ETH_EBHAUL  "ethpod"
#define MQTT_LOCAL_MQTT_BROKER "192.168.245.254:1883"
#define MAX_BUF_SIZE 256
#define VERSION_BUFF 64

#define OVS_ENABLED    "/sys/module/openvswitch"

static bool isReserveModeActive = false;
static bool isPaceXF3 = false;
static bool isSkyHUB4 = false;
static bool isCBR2 = false;
bool isXB3Platform = false;
#define ETHBHAUL_SWITCH "/usr/sbin/deviceinfo.sh"
#define MESH_BHAUL_INETADDR "192.168.245.254"
#define MESH_BHAUL_INETMASK "255.255.255.0"
static bool s_SysEventHandler_ready = false;
extern  ANSC_HANDLE             bus_handle;

#ifndef DBUS_SUPPORT
extern MeshRbusPublishEvent  meshRbusPublishEvent[];
#endif

static pthread_t mq_server_tid; // server thread id
static pthread_t lease_server_tid; // dnsmasq lease thread id
int sysevent_fd;
int sysevent_fd_gs;
token_t sysevent_token_gs;
token_t sysevent_token;
static pthread_t sysevent_tid;

int mac_index = 0;
MeshDscp dscp_mac_list;

const char urlOld[] = "NOC-URL-DEV";
const char urlDefault[] = "NOC-URL-PROD";
const char meshServiceName[] = "meshwifi";
const char meshDevFile[] = "/nvram/mesh-dev.flag";
static bool gmssClamped = false;
pthread_mutex_t mesh_handler_mutex = PTHREAD_MUTEX_INITIALIZER;
#define _DEBUG 1
#define THREAD_NAME_LEN 16 //length is restricted to 16 characters, including the terminating null byte

#if defined(ONEWIFI) || defined(WAN_FAILOVER_SUPPORTED) || defined(GATEWAY_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
extern char g_Subsystem[32];

#if defined(ONEWIFI) || defined(WAN_FAILOVER_SUPPORTED)
#define      REMOTE_INTERFACE_NAME             "brRWAN"
#endif //WAN_FAILOVER_SUPPORTED

#ifndef DBUS_SUPPORT
#if defined(WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
#define      RBUS_DEVICE_MODE        "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode"
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
#define      RBUS_STA_CONNECT_TIMEOUT "Device.WiFi.STAConnectionTimeout"
#endif
#if defined(ONEWIFI) || defined(WAN_FAILOVER_SUPPORTED)
#define      RBUS_WAN_CURRENT_ACTIVE_INTERFACE "Device.X_RDK_WanManager.CurrentActiveInterface"
#endif //WAN_FAILOVER_SUPPORTED
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
#define      RBUS_GATEWAY_PRESENT    "Device.X_RDK_GatewayManagement.ExternalGatewayPresent"
#endif
#if defined(ONEWIFI)
#define      RBUS_STA_STATUS         "Device.WiFi.STA.*.Connection.Status"
#define      RBUS_STA_STATUS_INDEX   "Device.WiFi.STA.%d.Connection.Status"
#endif

#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
#define      TR181_GLOBAL_FEATURE_PARAM_GFO_SUPPORTED    "Device.X_RDK_Features.GatewayFailover.Enable"
#endif

typedef enum
{
#if defined(ONEWIFI)
    MESH_RBUS_STA_STATUS,
#endif
#if defined(WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
    MESH_RBUS_DEVICE_MODE,
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    MESH_RBUS_STA_CONNECT_TIMEOUT,
#endif
#if defined(WAN_FAILOVER_SUPPORTED)
    MESH_RBUS_WAN_CURRENT_ACTIVE_INTERFACE,
#endif //WAN_FAILOVER_SUPPORTED
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
    MESH_RBUS_GATEWAY_PRESENT,
#endif
    MESH_RBUS_EVENT_TOTAL
} eMeshRbusEventType;

typedef struct _MeshRbusEvent
{
   eMeshRbusEventType eType;
   char name[MAX_IFNAME_LEN]; 
   bool status;
   bool feature_supported;
}MeshRbusEvent;

MeshRbusEvent  meshRbusEvent[] = {
#if defined(ONEWIFI)
    {MESH_RBUS_STA_STATUS,                       RBUS_STA_STATUS,                      false,                      true},
#endif
#if defined(WAN_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
    {MESH_RBUS_DEVICE_MODE,                      RBUS_DEVICE_MODE,                     false,                      true},
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    {MESH_RBUS_STA_CONNECT_TIMEOUT,              RBUS_STA_CONNECT_TIMEOUT,             false,                      true},
#endif
#if defined(WAN_FAILOVER_SUPPORTED)
    {MESH_RBUS_WAN_CURRENT_ACTIVE_INTERFACE,     RBUS_WAN_CURRENT_ACTIVE_INTERFACE,    false,                      true},
#endif //WAN_FAILOVER_SUPPORTED
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
    {MESH_RBUS_GATEWAY_PRESENT,                  RBUS_GATEWAY_PRESENT,                 false,                      true}
#endif
};
#endif //DBUS_SUPPORT
#endif //defined(ONEWIFI) || defined(WAN_FAILOVER_SUPPORTED) || defined(GATEWAY_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)

#ifndef DBUS_SUPPORT
extern rbusHandle_t handle;

#define      RBUS_SPEEDTEST_STATUS   "Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.Status"
#define      RBUS_SPEEDTEST_TIMEOUT  "Device.IP.Diagnostics.X_RDK_SpeedTest.SubscriberUnPauseTimeOut"
rbusError_t rbusGetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t rbusGetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t rbusEventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish);

rbusDataElement_t meshRbusDataElements[NUM_OF_RBUS_PARAMS] = {
        {EVENT_MWO_TOS_CONFIGURATION, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}},
        {EVENT_MWO_CLIENT_TO_PROFILE_MAP_EVENT, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}}
#ifdef WAN_FAILOVER_SUPPORTED
        ,{EVENT_MESH_WAN_LINK, RBUS_ELEMENT_TYPE_EVENT, {rbusGetBoolHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}},
        {EVENT_MESH_WAN_IFNAME, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, NULL, NULL}},
	{EVENT_MESH_BACKHAUL_IFNAME, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}},
        {EVENT_MESH_ETHERNETBHAUL_UPLINK, RBUS_ELEMENT_TYPE_EVENT, {rbusGetBoolHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}}
#endif
        ,{EVENT_RECORDER_ENABLE, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}},
        {EVENT_CHANNEL_KEEPOUT, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}},
        {EVENT_HD_RECOMMENDATION, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}},
        {EVENT_CHANNELPLAN_COMMIT, RBUS_ELEMENT_TYPE_EVENT, {rbusGetStringHandler, NULL, NULL, NULL, rbusEventSubHandler, NULL}}
};
#endif

#define      ST_TR181_STATUS_STARTING 1
#define      ST_TR181_STATUS_COMPLETE 5

#ifdef WAN_FAILOVER_SUPPORTED
static bool wfo_mode = false;
static bool meshWANStatus = false;
static char *meshWANIfname = NULL;
static bool meshETHBhaulUplink = false;
bool get_wan_bridge();
bool get_eth_interface(char * eth_interface);
#endif

#if defined(WAN_FAILOVER_SUPPORTED) || defined(ONEWIFI) || defined(GATEWAY_FAILOVER_SUPPORTED)
MeshStaStatus_node sta;
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
static int device_mode = DEFAULT_MODE;
#endif
unsigned char mesh_backhaul_ifname[MAX_IFNAME_LEN];
#endif
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
static int is_uplink_tid_exist = 0;
#ifndef DBUS_SUPPORT
static int gateway_present = -1;
static pthread_t tid_handle;
#endif
#endif

static int dnsmasqFd;
static struct sockaddr_in dnsserverAddr;

extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;
static bool oneWifiEnabled = false;
static bool wanFailOverEnabled = false;

bool g_offchanvalFound = false;
bool g_offchanEnabled = false;

// Mesh Status structure
typedef struct
{
    eMeshWifiStatusType    mStatus;
    char                  *mStr;
} MeshStatus_item;

MeshStatus_item meshWifiStatusArr[] = {
    {MESH_WIFI_STATUS_OFF,     "Off"},
    {MESH_WIFI_STATUS_INIT,    "Init"},
    {MESH_WIFI_STATUS_MONITOR, "Monitor"},
    {MESH_WIFI_STATUS_FULL,    "Full"}
};

// Mesh State structure
typedef struct
{
    eMeshStateType      mState;
    char                *mStr;
} MeshState_item;

MeshState_item meshStateArr[] = {
    {MESH_STATE_FULL,      "Full"},
    {MESH_STATE_MONITOR,   "Monitor"},
    {MESH_STATE_WIFI_RESET,"Reset"}
};

// This Array should have MESH_SYNC_MSG_TOTAL-1 entries
MeshSync_MsgItem meshSyncMsgArr[] = {
    {MESH_WIFI_RESET,                       "MESH_WIFI_RESET",                      "wifi_init"},
    {MESH_WIFI_RADIO_CHANNEL,               "MESH_WIFI_RADIO_CHANNEL",              "wifi_RadioChannel"},
    {MESH_WIFI_RADIO_CHANNEL_MODE,          "MESH_WIFI_RADIO_CHANNEL_MODE",         "wifi_RadioChannelMode"},
    {MESH_WIFI_SSID_NAME,                   "MESH_WIFI_SSID_NAME",                  "wifi_SSIDName"},
    {MESH_WIFI_SSID_ADVERTISE,              "MESH_WIFI_SSID_ADVERTISE",             "wifi_SSIDAdvertisementEnable"},
    {MESH_WIFI_AP_SECURITY,                 "MESH_WIFI_AP_SECURITY",                "wifi_ApSecurity"},
    {MESH_WIFI_AP_KICK_ASSOC_DEVICE,        "MESH_WIFI_AP_KICK_ASSOC_DEVICE",       "wifi_kickApAssociatedDevice"},
    {MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES,   "MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES",  "wifi_kickAllApAssociatedDevice"},
    {MESH_WIFI_AP_ADD_ACL_DEVICE,           "MESH_WIFI_AP_ADD_ACL_DEVICE",          "wifi_addApAclDevice"},
    {MESH_WIFI_AP_DEL_ACL_DEVICE,           "MESH_WIFI_AP_DEL_ACL_DEVICE",          "wifi_delApAclDevice"},
    {MESH_WIFI_MAC_ADDR_CONTROL_MODE,       "MESH_WIFI_MAC_ADDR_CONTROL_MODE",      "wifi_MacAddressControlMode"},
    {MESH_SUBNET_CHANGE,                    "MESH_SUBNET_CHANGE",                   "subnet_change"},
    {MESH_URL_CHANGE,                       "MESH_URL_CHANGE",                      "mesh_url"},
    {MESH_WIFI_STATUS,                      "MESH_WIFI_STATUS",                     "mesh_status"},
    {MESH_WIFI_ENABLE,                      "MESH_WIFI_ENABLE",                     "mesh_enable"},
    {MESH_STATE_CHANGE,                     "MESH_STATE_CHANGE",                    "mesh_state"},
    {MESH_WIFI_TXRATE,                      "MESH_WIFI_TXRATE",                     "wifi_TxRate"},
    {MESH_CLIENT_CONNECT,                   "MESH_CLIENT_CONNECT",                  "client_connect"},
    {MESH_DHCP_RESYNC_LEASES,               "MESH_DHCP_RESYNC_LEASES",              "lease_resync"},
    {MESH_DHCP_ADD_LEASE,                   "MESH_DHCP_ADD_LEASE",                  "lease_add"},
    {MESH_DHCP_REMOVE_LEASE,                "MESH_DHCP_REMOVE_LEASE",               "lease_remove"},
    {MESH_DHCP_UPDATE_LEASE,                "MESH_DHCP_UPDATE_LEASE",               "lease_update"},
    {MESH_WIFI_RADIO_CHANNEL_BW,            "MESH_WIFI_RADIO_CHANNEL_BW",           "channel_update"},
    {MESH_ETHERNET_MAC_LIST,                "MESH_ETHERNET_MAC_LIST",               "process_eth_mac"},
    {MESH_RFC_UPDATE,                       "MESH_RFC_UPDATE",                      "eb_enable"},
    {MESH_TUNNEL_SET,                       "MESH_TUNNEL_SET",                      "tunnel"},
    {MESH_TUNNEL_SET_VLAN,                  "MESH_TUNNEL_SET_VLAN",                 "tunnel_vlan"},
    {MESH_REDUCED_RETRY,                    "MESH_REDUCED_RETRY",                   "mesh_conn_opt_retry"},
    {MESH_WIFI_SSID_CHANGED,                "MESH_WIFI_SSID_CHANGED",               "wifi_SSIDChanged"},
    {MESH_WIFI_RADIO_OPERATING_STD,         "MESH_WIFI_RADIO_OPERATING_STD",        "wifi_RadioOperatingStd"},
    {MESH_SYNC_SM_PAUSE,                    "MESH_SYNC_SM_PAUSE",                   "mesh_sm_pause"},
    {MESH_WIFI_OFF_CHAN_ENABLE,             "MESH_WIFI_OFF_CHAN_ENABLE",            "wifi_OffChannelScanEnable"},
    {MESH_GATEWAY_ENABLE,                   "MESH_GATEWAY_ENABLE",                  "mesh_switch_to_gateway"},
    {MESH_WIFI_OPT_MODE,                    "MESH_WIFI_OPT_MODE",                   "mesh_optimized_mode"},
    {MESH_WIFI_OPT_BROKER,                  "MESH_WIFI_OPT_BROKER",                 "mwo_mqtt_config"},
    {MESH_WIFI_REINIT_PERIOD,               "MESH_WIFI_REINIT_PERIOD",              "hcm_reinit_period"},
    {MESH_OPT_ENABLE_MODE_BROKER_URL,       "MESH_OPT_ENABLE_MODE_BROKER_URL",      "offline_mqtt_broker"},
    {MESH_OPT_ENABLE_MODE_BROKER_PORT,      "MESH_OPT_ENABLE_MODE_BROKER_PORT",     "offline_mqtt_port"},
    {MESH_OPT_ENABLE_MODE_BROKER_TOPIC,     "MESH_OPT_ENABLE_MODE_BROKER_TOPIC",    "offline_mqtt_topic"},
    {MESH_WIFI_MOTION,                      "MESH_WIFI_MOTION",                     "wifi_motion_enable"},
    {MESH_CA_CERT,                          "MESH_CA_CERT",                         "comodo_ca_enable"}
#ifdef ONEWIFI
    ,
    {MESH_SYNC_STATUS,                      "MESH_SYNC_STATUS",                     "mesh_led_status"},
    {MESH_CONTROLLER_STATUS,                "MESH_CONTROLLER_STATUS",               "mesh_controller_status"},
    {MESH_WIFI_EXTENDER_MODE,               "MESH_WIFI_EXTENDER_MODE",              "onewifi_XLE_Extender_mode"},
    {MESH_ADD_DNSMASQ,                      "MESH_ADD_DNSMASQ",                     "dhcp_conf_change"},
    {MESH_XLE_MODE_CLOUD_CTRL_RFC,          "MESH_XLE_MODE_CLOUD_CTRL_RFC",         "xle_mode_cloud_ctrl_rfc"}
#endif
#ifdef WAN_FAILOVER_SUPPORTED
    ,
    {MESH_BACKUP_NETWORK,                   "MESH_BACKUP_NETWORK",                  "mesh_wan_linkstatus"},
    {MESH_WFO_ENABLED,                      "MESH_WFO_ENABLED",                     "mesh_wfo_enabled"}
#endif
#ifdef ONEWIFI
    ,
    {MESH_GET_STAINFO,                      "MESH_GET_STAINFO",                     "mesh_get_stainfo"}
    ,
    {MESH_BRHOME_IP,                        "MESH_BRHOME_IP",                        "remote_ssh_server_ip"},
    {MESH_TRIGGER_DISASSOC,                 "MESH_TRIGGER_DISASSOC",                "mesh_trigger_disaasociation_req"}
#endif
  ,
  {MESH_EBH_STATUS,                       "MESH_EBH_STATUS",                      "ebh_status"},
  {MESH_EBH_INFO,                         "MESH_EBH_INFO",                        "ebh_info"},
  {MESH_WIFI_DYNAMIC_PROFILE,             "MESH_WIFI_DYNAMIC_PROFILE",            "wifiDynamicProfile"},
  {MESH_FIREWALL_START,                   "MESH_FIREWALL_START",                  "firewall-status"},
  {MESH_DSCP_INHERIT_ENABLE,              "MESH_DSCP_INHERIT_ENABLE",             "dscp_inherit_enable"},
  {MESH_RECORDER_ENABLE,                  "MESH_RECORDER_ENABLE",                 "recorder_enable"}
    };
typedef struct
{
    eMeshIfaceType  mType;
    char           *mStr;
} MeshIface_item;

MeshIface_item meshIfaceArr[] = {
        {MESH_IFACE_NONE,     "None"},
        {MESH_IFACE_ETHERNET, "Ethernet"},
        {MESH_IFACE_MOCA,     "MoCA"},
        {MESH_IFACE_WIFI,     "WiFi"},
        {MESH_IFACE_OTHER,    "Other"}};


/**************************************************************************/
/*      LOCAL FUNCTIONS:                                                  */
/**************************************************************************/
static void Mesh_sendDhcpLeaseUpdate(int msgType, char *mac, char *ipaddr, char *hostname, char *fingerprint);
static void Mesh_sendDhcpLeaseSync(void);
static void Mesh_sendRFCUpdate(const char *param, const char *val, eRfcType type);
static void* msgQServer(void *data);
static int  msgQSend(MeshSync *data);
static void Mesh_SetDefaults(ANSC_HANDLE hThisObject);
static bool Mesh_Register_sysevent(ANSC_HANDLE hThisObject);
static void *Mesh_sysevent_handler(void *data);
static void Mesh_sendReducedRetry(bool value);
void Mesh_sendWifiMotionEnable(bool value);
static void Mesh_sendmeshWifiOptimization(eWifiOptimizationMode mode);
static void Mesh_sendmeshWifiMqtt(char *val);
#if defined(WAN_FAILOVER_SUPPORTED)
void Mesh_backup_network(char *ifname, eMeshDeviceMode type, bool status);
#endif
#ifdef ONEWIFI
int Mesh_vlan_network(char *ifname);
int Mesh_rebootDevice();
void  Mesh_sendCurrentSta();
void Mesh_setXleModeChangeRbus(bool enable);
void Mesh_sendStaInterface(char * mesh_sta,char *bssid, bool status);
int get_sta_active_interface_name();
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
static void Mesh_sendEbhStatusRequest();
#endif
#if ((!defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)) && !defined (DBUS_SUPPORT))
void rbus_get_gw_present();
#endif
static int Mesh_Init(ANSC_HANDLE hThisObject);
static void Mesh_InitEthHost_Sync(void);
static void changeChBandwidth( int, int);
static void Mesh_ModifyPodTunnel(MeshTunnelSet *conf);
static void Mesh_ModifyPodTunnelVlan(MeshTunnelSetVlan *conf, bool is_ovs);
static BOOL is_configure_wifi_enabled();
#ifdef WAN_FAILOVER_SUPPORTED
bool Mesh_ExtenderBridge(char *ifname);
#endif

static char EthPodMacs[MAX_POD_COUNT][MAX_MAC_ADDR_LEN];
static int eth_mac_count = 0;

static ssize_t leaseServerRead(int fd, MeshNotify* notify, int timeout);

static void off_chan_scan_status_set()
{
    MeshInfo("Sending off chan status to msgQ \n");
    MeshSync mMsg = {0};
    if (g_offchanvalFound)
    {
        g_offchanvalFound = false;
        // Set sync message type
        mMsg.msgType = MESH_WIFI_OFF_CHAN_ENABLE;
        mMsg.data.wifiOffChannelScanEnable.enable = g_offchanEnabled;
        msgQSend(&mMsg);
    }
    return;
}

static int Get_MeshSyncType(char * name ,eMeshSyncType *type_ptr)
{
    errno_t rc       = -1;
    int     ind      = -1;
    int strlength;
    int i;

    if( (name == NULL) || (type_ptr == NULL) )
       return 0;

    strlength = strlen( name );
    /*CID *336357  Overrunning array meshSyncMsgArr of 49 12-byte elements at element index 50 (byte offset 611) using index i*/
    int arraySize = sizeof(meshSyncMsgArr) / sizeof(meshSyncMsgArr[0]);
    for (i = 0; i < arraySize; i++) {

        rc = strcmp_s(name, strlength, meshSyncMsgArr[i].sysStr, &ind);
        ERR_CHK(rc);
        if((ind==0) && (rc == EOK))
        {
            *type_ptr =  meshSyncMsgArr[i].mType ;
            return 1;
        }
    }
    
    return 0;
}

/**
 * @brief Mesh Agent Interface lookup function
 *
 * This function will take an interface string and convert it to an enum value
 */
static eMeshIfaceType Mesh_IfaceLookup(char *iface)
{
    eMeshIfaceType ret = MESH_IFACE_OTHER;
    errno_t rc       = -1;
    int     ind      = -1;
    if (iface != NULL && iface[0] != '\0')
    {
        int i;
        int strlength;
        strlength = strlen( iface );
        for (i = 0; i < MESH_IFACE_TOTAL; i++) {
            rc = strcmp_s(iface,strlength,meshIfaceArr[i].mStr,&ind);
            ERR_CHK(rc);          
            if((ind == 0) && (rc == EOK))
            {
                ret = meshIfaceArr[i].mType;
                break;
            }
        }
    }

    return ret;
}

/**
 * @brief Mesh Agent Status lookup function
 *
 * This function will take an interface string and convert it to an enum value
 */
static eMeshWifiStatusType Mesh_WifiStatusLookup(char *status)
{
    eMeshWifiStatusType ret = MESH_WIFI_STATUS_OFF;
    errno_t rc       = -1;
    int     ind      = -1;

    if (status != NULL && status[0] != '\0')
    {
        int i;
        int strlength;
        strlength = strlen( status );
        for (i = 0; i < MESH_WIFI_STATUS_TOTAL; i++) {
            rc = strcmp_s(status,strlength,meshWifiStatusArr[i].mStr,&ind);
            ERR_CHK(rc);       
            if((ind == 0) && (rc == EOK))
            {
                ret = meshWifiStatusArr[i].mStatus;
                break;
            }
        }
    }

    return ret;
}

static bool isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa = {0};
    char ip[16] = {0};
    errno_t rc = -1;

    if(ipAddress == NULL)
    {
       MeshError("ipAddress is NULL\n");
       return FALSE;
    }

    rc = strncpy_s(ip, sizeof(ip), ipAddress, 13);
    if(rc != EOK)
    {
       ERR_CHK(rc);
       MeshError("Error in copying ipAddress - %s\n", ipAddress);
       return FALSE;
    }
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

static int Mesh_DnsmasqSock(void)
{
 if(!dnsmasqFd)
 {
  FILE *cmd;
  errno_t rc = -1;
  char armIP[32] = {'\0'};;
  cmd = v_secure_popen("r","grep ARM_INTERFACE_IP /etc/device.properties | cut -d '=' -f2");
  if(cmd == NULL) {
       return 0;
   }
  fgets(armIP, sizeof(armIP), cmd);
  v_secure_pclose(cmd);
  dnsmasqFd = socket(PF_INET, SOCK_DGRAM, 0);
  if( dnsmasqFd < 0)
    return 0;
  dnsserverAddr.sin_family = AF_INET;
  dnsserverAddr.sin_port = htons(47030);
  if((!isValidIpAddress(armIP)) || (isCBR2))  {
   MeshInfo("Socket bind to localhost\n");
   dnsserverAddr.sin_addr.s_addr = inet_addr(LOCAL_HOST);
  } else
  {
   MeshInfo("Socket bind to ARM IP %s\n", armIP);
   dnsserverAddr.sin_addr.s_addr = inet_addr(armIP);
  }
  rc = memset_s(dnsserverAddr.sin_zero, sizeof(dnsserverAddr.sin_zero), '\0', sizeof(dnsserverAddr.sin_zero));
  ERR_CHK(rc);
  MeshInfo("Created dnsmasq socket for Eth Bhaul mac update\n");
 }
 return 1;
}

static bool Mesh_PodAddress(char *mac, bool add)
{
  int i;
  errno_t rc = -1;
  int ind = -1;
  int strlength;
  
  if (mac == NULL)
  {
        MeshError("Error - Pod mac address is NULL\n");
	return FALSE;
  }

  strlength = strlen( mac );
  for(i =0; i < eth_mac_count; i++)
  {
   rc = strcmp_s(mac, strlength ,EthPodMacs[i] ,&ind);
   ERR_CHK(rc);       
   if((ind == 0) && (rc == EOK))
   {
    MeshInfo("Pod mac detected as connected client, ignore update\n");
    return TRUE;
   }
  }
  if( add && (eth_mac_count < MAX_POD_COUNT) ) {
   MeshInfo("Adding the Ethernet pod mac in the local copy mac: %s idx: %d\n", mac, eth_mac_count);
    rc = strcpy_s(EthPodMacs[eth_mac_count], MAX_MAC_ADDR_LEN, mac);
   if(rc != EOK)
   {
      ERR_CHK(rc);
      MeshError("Error in copying to Ethernet pod mac\n");
      return FALSE;
   }
   eth_mac_count++;
  }
  else
  {
   MeshInfo("Send the Connect event for this client as normal client: %s\n", mac);
  }

  return FALSE;
}

/**
 *  @brief MeshAgent Process Send Pod mac to dnsmasq for filtering
 *
 *  This function will send Pod mac addr
 *  to dnsmasq for the purpose of Vendor ID filtering
 *  when Pod connected via ethernet
 */
void Mesh_SendEthernetMac(char *mac)
{
  errno_t rc = -1;
 if(Mesh_DnsmasqSock())
 {
  PodMacNotify msg = {{0},0};
  PodMacNotify *sendBuff;

  sendBuff = &msg;
  msg.msgType = g_pMeshAgent->PodEthernetBackhaulEnable ?  START_POD_FILTER : STOP_POD_FILTER;
  rc = strcpy_s(msg.mac, MAX_MAC_ADDR_LEN, mac);
  if(rc != EOK)
  {
      ERR_CHK(rc);
      MeshError("Error in sending the mac via socket\n");
      close(dnsmasqFd);
      dnsmasqFd=0;
      return;
  } 

  if(dnsmasqFd) {
    /* Coverity Issue Fix - CID:113076 : Buffer Over Run */
    /* Coverity Fix CID: 110417 CHECKED_RETURN */
   if(sendto(dnsmasqFd, (const char*)sendBuff, sizeof(PodMacNotify), 0, (struct sockaddr *)&dnsserverAddr,(sizeof dnsserverAddr)) ==-1)
     MeshError("Error sending Pod mac address to dnsmasq\n");
   else
     MeshInfo("Pod mac address sent to dnsmasq MAC: %s\n", mac);
  }
  else
     MeshError ("Error sending Pod mac address to dnsmasq, Socket not ready MAC: %s\n", mac);

  close(dnsmasqFd);
  dnsmasqFd=0;
 }
 else {
    MeshError("Socket failed in %s\n", __FUNCTION__);
 }

  return;
}

static int Mesh_getIpOctet(char *Ip, int octet)
{
    char *token = NULL, *rlocalIp = NULL;
    char localIp [MAX_IP_LEN] = {'\0'};
    errno_t rc = -1;

    rc = strcpy_s(localIp, sizeof(localIp), Ip);
    ERR_CHK(rc);
    rlocalIp = localIp;
    while ((--octet >= 0) && (token = strtok_r(rlocalIp, ".", &rlocalIp)));
    return (token ? atoi(token) : -1);
}

static void Mesh_SendPodAddresses()
{
 int i=0;
 bool macPresent = false;
 for(i=0; i < eth_mac_count; i++)
 {
  MeshInfo("Send pod address %s to dnsmasq %s\n", EthPodMacs[i], __FUNCTION__);
  Mesh_SendEthernetMac( EthPodMacs[i]);
  macPresent = true;
 }

 if( !macPresent && g_pMeshAgent->PodEthernetBackhaulEnable) {
  MeshWarning("Potential issue of lost Pod mac-addresses, Resync from the RM again\n");
  Mesh_sendRFCUpdate("PodEthernetGreBackhaul.Enable", "true", rfc_boolean);
 }
}

/**
 *  @brief MeshAgent Process Sync Message
 *
 *  This function will take a sync message and process it
 */
static void Mesh_ProcessSyncMessage(MeshSync rxMsg)
{
    // Parse out the messages and send the sysevents
    // Check to see if this is a valid message
    /*CID 143971  Overrunning array meshSyncMsgArr of 49 12-byte elements at element index 50 (byte offset 611) using index rxMsg.msgType */

    // Check if rxMsg.msgType is within bounds
    if (rxMsg.msgType >= MESH_SYNC_MSG_TOTAL || rxMsg.msgType < 0 || rxMsg.msgType >= sizeof(meshSyncMsgArr) / sizeof(meshSyncMsgArr[0]))
    {
        MeshError("Error unknown message type %d - skipping\n", rxMsg.msgType);
        return;
    }

    MeshInfo("%s - %s message received.\n", __FUNCTION__, meshSyncMsgArr[rxMsg.msgType].msgStr);

    switch (rxMsg.msgType) {
    case MESH_WIFI_RADIO_CHANNEL:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%d",
                rxMsg.data.wifiRadioChannel.index,
                rxMsg.data.wifiRadioChannel.channel);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_RADIO_CHANNEL_MODE:
    {
        char cmd[256];
        /* Coverity Issue Fix - CID:124800 : Printf args*/
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s|%s|%s|%s",
                rxMsg.data.wifiRadioChannelMode.index,
                rxMsg.data.wifiRadioChannelMode.channelMode,
                (rxMsg.data.wifiRadioChannelMode.gOnlyFlag?"true":"false"),
                (rxMsg.data.wifiRadioChannelMode.nOnlyFlag?"true":"false"),
                (rxMsg.data.wifiRadioChannelMode.acOnlyFlag?"true":"false")
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL_MODE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_RADIO_OPERATING_STD:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s",
                rxMsg.data.wifiRadioOperatingStd.index,
                rxMsg.data.wifiRadioOperatingStd.channelMode
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_RADIO_OPERATING_STD].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_SSID_NAME:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s",
                rxMsg.data.wifiSSIDName.index,
                rxMsg.data.wifiSSIDName.ssid
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_SSID_NAME].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_SSID_CHANGED:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%d|%s",
                rxMsg.data.wifiSSIDChanged.index,
                rxMsg.data.wifiSSIDChanged.enable,
                rxMsg.data.wifiSSIDChanged.ssid
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_SSID_CHANGED].sysStr, cmd, 0, false);
    }
    break;
#if defined(ONEWIFI)
    case MESH_WIFI_EXTENDER_MODE:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%s",
                rxMsg.data.onewifiXLEExtenderMode.InterfaceName);
        MeshError("Notify onewifi for MESH_WIFI_EXTENDER_MODE cmd:%s\n",cmd);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_EXTENDER_MODE].sysStr, cmd, 0, false);
    }
    break;
#endif
    case MESH_WIFI_SSID_ADVERTISE:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s",
                rxMsg.data.wifiSSIDAdvertise.index,
                (rxMsg.data.wifiSSIDAdvertise.enable?"true":"false")
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_SSID_ADVERTISE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_SECURITY:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s|%s|%s",
                rxMsg.data.wifiAPSecurity.index,
                rxMsg.data.wifiAPSecurity.passphrase,
                rxMsg.data.wifiAPSecurity.secMode,
                rxMsg.data.wifiAPSecurity.encryptMode
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_SECURITY].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_KICK_ASSOC_DEVICE:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s",
                rxMsg.data.wifiAPKickAssocDevice.index,
                rxMsg.data.wifiAPKickAssocDevice.mac
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_KICK_ASSOC_DEVICE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d",
                rxMsg.data.wifiAPKickAllAssocDevices.index
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_ADD_ACL_DEVICE:
    {
        char cmd[256] = {0};
        /*Coverity Fix: CID 57148 DC.STRING_BUFFER */
        snprintf(cmd,sizeof(cmd), "MESH|%d|%s",
                rxMsg.data.wifiAPAddAclDevice.index,
                rxMsg.data.wifiAPAddAclDevice.mac
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_ADD_ACL_DEVICE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_AP_DEL_ACL_DEVICE:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s",
                rxMsg.data.wifiAPDelAclDevice.index,
                rxMsg.data.wifiAPDelAclDevice.mac
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_AP_DEL_ACL_DEVICE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_MAC_ADDR_CONTROL_MODE:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "MESH|%d|%s|%s",
                rxMsg.data.wifiMacAddrControlMode.index,
                (rxMsg.data.wifiMacAddrControlMode.isEnabled?"true":"false"),
                (rxMsg.data.wifiMacAddrControlMode.isBlacklist?"true":"false")
        );
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_MAC_ADDR_CONTROL_MODE].sysStr, cmd, 0, false);
    }
    break;
    case MESH_WIFI_STATUS:
    {
        char cmd[256];

        g_pMeshAgent->meshStatus = rxMsg.data.wifiStatus.status;

        snprintf(cmd, sizeof(cmd), "MESH|%s",meshWifiStatusArr[rxMsg.data.wifiStatus.status].mStr);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_STATUS].sysStr, cmd, 0, true);

    }
    break;
    case MESH_WIFI_RADIO_CHANNEL_BW:
    {
        MeshInfo("Recieved Channel BW change notification radioId = %d channel = %d\n",
                  rxMsg.data.wifiRadioChannelBw.index, rxMsg.data.wifiRadioChannelBw.bw);
        changeChBandwidth(rxMsg.data.wifiRadioChannelBw.index, rxMsg.data.wifiRadioChannelBw.bw);
    }
    break;
    case MESH_TUNNEL_SET:
    {
      MeshInfo("Received Tunnel creation\n");
      Mesh_ModifyPodTunnel((MeshTunnelSet *)&rxMsg.data);
    }
    break;
    case MESH_TUNNEL_SET_VLAN:
    {
      MeshInfo("Received Tunnel vlan creation\n");
      Mesh_ModifyPodTunnelVlan((MeshTunnelSetVlan *)&rxMsg.data, true);
    }
    break;
    case MESH_ETHERNET_MAC_LIST:
    {
        int rc = -1;

        if(meshAddPod(rxMsg.data.ethMac.mac) == false) {
            MeshError("Failed to add pod to state list\n");
        }

        if( g_pMeshAgent->PodEthernetBackhaulEnable)
        {
            rc= v_secure_system( ETHBHAUL_SWITCH " -eb_enable");
            if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
            {
                MeshError("%s -eb_enable : Ethernet backhaul enable failed = %d\n", ETHBHAUL_SWITCH, WEXITSTATUS(rc));
            }
            Mesh_SendEthernetMac(rxMsg.data.ethMac.mac);
        }
        else
            MeshInfo("Ethernet bhaul disabled, ignoring the Pod mac update\n");

        Mesh_PodAddress( rxMsg.data.ethMac.mac, TRUE);
        if((g_pMeshAgent->meshWifiOptimizationMode == MESH_MODE_MONITOR || g_pMeshAgent->meshWifiOptimizationMode == MESH_MODE_ENABLE) && (eth_mac_count >0))
        {
            Mesh_SetMeshWifiOptimizationMode(MESH_MODE_DISABLE, false, true);
            MeshInfo("HCM Monitor/Enable Mode cant be configured if pod present, Changing rfc to Disabled\n");
        }
    }
    break;
#ifdef WAN_FAILOVER_SUPPORTED
    case MESH_BACKUP_NETWORK:
    {
        int rc =-1;

        if (g_pMeshAgent->IsPodConnect != true)
        {
            if (g_pMeshAgent->dscpInheritRfcEnable && g_pMeshAgent->IsdscpConfigEnabled)
            {
                rc= v_secure_system("systemctl start greinheritance.service");
                if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
                     MeshError("Failed systemctl start greinheritance.service  rc = %d\n",WEXITSTATUS(rc));
                 MeshInfo("Insert kernel module xmeshgre.ko \n");
            }
            g_pMeshAgent->IsPodConnect = true;
        }
        Mesh_backup_network(rxMsg.data.networkType.ifname, rxMsg.data.networkType.type, rxMsg.data.networkType.status);
    }
    break;
#endif
#ifdef ONEWIFI
    case MESH_GET_STAINFO:
    {
        MeshInfo(("Received MESH_GET_STAINFO sync message.\n"));
        Mesh_sendCurrentSta();
    }
    break;
    case MESH_GATEWAY_ENABLE:
    {
        MeshInfo("Received MESH_GATEWAY_ENABLE sync message, rfc : %d.\n",g_pMeshAgent->XleModeCloudCtrlEnable);
#ifndef DBUS_SUPPORT
        if (g_pMeshAgent->XleModeCloudCtrlEnable)
            Mesh_setXleModeChangeRbus((rxMsg.data.gateway.enable?true:false));
#endif
    }
    break;
    case MESH_BRHOME_IP:
    {
        MeshInfo("Received event MESH_BRHOME_IP %s\n", rxMsg.data.brhomeIP.ip);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_BRHOME_IP].sysStr, rxMsg.data.brhomeIP.ip, 0, false);
#ifndef DBUS_SUPPORT
	publishRBUSEvent(MESH_RBUS_PUBLISH_BACKHAUL_IFNAME, (void *)mesh_backhaul_ifname,handle);
#endif 
    }
    break;
    case MESH_ADD_DNSMASQ:
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),"interface=%s|dhcp-range=%s,%s,255.255.255.0,infinite",
                rxMsg.data.STADnsMasqInfo.ifname, rxMsg.data.STADnsMasqInfo.dhcp_start,
                rxMsg.data.STADnsMasqInfo.dhcp_end);
        MeshInfo("Received MESH_ADD_DNSMASQ with cmd:%s,leaseTime:%d\n",
                cmd, rxMsg.data.STADnsMasqInfo.lease_time);
        //setIgnoreLinkEvent(true);
        //Mesh_SyseventSetStr(meshSyncMsgArr[MESH_ADD_DNSMASQ].sysStr, cmd, 0, false);
        break;
    }
    case MESH_SYNC_STATUS:
    {
        MeshInfo(("Received MESH_SYNC_STATUS sync message.\n"));
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
        handle_led_status(rxMsg.data.syncStatus.status, device_mode);
#endif
    }
    break;
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    case MESH_EBH_STATUS:
    {
        MeshInfo(("Received MESH_EBH_STATUS sync message.\n"));
        if(!rxMsg.data.ebhStatus.enabled)
        {
            MeshInfo("Got RBUS_STA_CONNECT_TIMEOUT trigger reboot\n");
#ifdef ONEWIFI
            Mesh_rebootDevice();
#endif
        }
        else
        {
            MeshInfo("Skiping RBUS_STA_CONNECT_TIMEOUT because xle is connected though eth backhaul\n");
        }
    }
    break;
#endif
    case MESH_TRIGGER_DISASSOC:
    {
        MeshInfo(("Received MESH_TRIGGER_DISASSOC\n"));
#ifndef DBUS_SUPPORT
        int rc = -1;
        int connect = rxMsg.data.triggerStatus.status;
        rbusValue_t value;

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, connect);

        rc = rbus_set(handle, MESH_STA_DISCONNECT_EVENT, value, NULL);
        if(rc == RBUS_ERROR_SUCCESS)
        {
            MeshInfo("Successfully Published MESH_TRIGGER_DISASSOC val:%d\n",connect);
        }
        else
        {
            MeshInfo("Error in publishing MESH_TRIGGER_DISASSOC val:%d\n",connect);
        }
        rbusValue_Release(value);
#endif
    }
    break;
#endif
    // the rest of these messages will not come from the Mesh vendor
    case MESH_SUBNET_CHANGE:
    case MESH_URL_CHANGE:
    case MESH_WIFI_ENABLE:
    case MESH_STATE_CHANGE:
    case MESH_WIFI_TXRATE:
    default:
        break;
    }
}

static void Mesh_logLinkChange(void)
{
    int rc = -1;

    if ((Mesh_GetEnabled("CaptivePortal_Enable") == true) && (is_configure_wifi_enabled() == true))
    {
        MeshError("Device in captive portal mode, pod will be non-operational\n");
        return;
    }

    if (access(POD_LINK_SCRIPT, F_OK) == 0) {
        rc= v_secure_system( POD_LINK_SCRIPT " &");
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("%s &: pod link script fail rc = %d\n", POD_LINK_SCRIPT, WEXITSTATUS(rc));
        }
    }
}

static int Mesh_CreateEthTunnel(int PodIdx, const char * bridge_ip, const char * pod_addr, const char * pod_dev, bool isOVSEnabled)
{
    int rc = -1;

    MeshDebug("Entering %s with PodIdx = %d, bridge_ip = %s, pod_addr = %s, and pod_dev = %s\n", __FUNCTION__, PodIdx, bridge_ip, pod_addr, pod_dev);
 
    if(isOVSEnabled) {
        rc = v_secure_system("/usr/bin/ovs-vsctl del-port %s ethpod%d", MESHBHAUL_BR, PodIdx);
    }
    rc = v_secure_system("ip link del ethpod%d", PodIdx);
    if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshWarning("Failed to delete ethpod%d, maybe it doesn't exist?\n", PodIdx);
    }

    rc = v_secure_system("ip link add ethpod%d type gretap local %s remote %s dev %s tos 1", PodIdx, bridge_ip, pod_addr, pod_dev);
    if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to create ethpod%d GRE tap with local IP: %s and remote IP %s\n", PodIdx, bridge_ip, pod_addr);
        return -1;
    }

    rc = v_secure_system("/sbin/ifconfig ethpod%d up", PodIdx);
    if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to bring ethpod%d up", PodIdx);
        return -1;
    }

    return 0;
}

int Mesh_EthBhaulPodVlanSetup(int PodIdx, bool isOvsMode)
{
    int rc = -1;
#ifdef WAN_FAILOVER_SUPPORTED
    char ethports[ETH_IFNAME_MAX_LEN] = {0};
    char * context = NULL;
    char *tok_ethport = NULL;
#endif

    MeshDebug("Entering %s with PodIdx = %d, and isOvsMode = %s\n", __FUNCTION__, PodIdx, (isOvsMode ? "true" : "false"));

    rc = v_secure_system("/sbin/vconfig add ethpod%d %d", PodIdx, XHS_VLAN);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to create VLAN for XHS\n");
        return rc;
    }

    rc = v_secure_system("/sbin/vconfig add ethpod%d %d", PodIdx, LNF_VLAN);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to create VLAN for LNF\n");
        return rc;
    }

    rc = v_secure_system("/sbin/ifconfig ethpod%d.%d up", PodIdx, XHS_VLAN);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to bring up XHS VLAN interface\n");
        return rc;
    }

    rc = v_secure_system("/sbin/ifconfig ethpod%d.%d up", PodIdx, LNF_VLAN);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to bring up LNF VLAN interface\n");
        return rc;
    }

    if(isOvsMode) {
        rc = v_secure_system("/usr/bin/ovs-vsctl del-port %s ethpod%d.%d", XHS_BR, PodIdx, XHS_VLAN);
        rc = v_secure_system("/usr/bin/ovs-vsctl add-port %s ethpod%d.%d", XHS_BR, PodIdx, XHS_VLAN);
    } else {
        rc = v_secure_system("brctl addif %s ethpod%d.%d", XHS_BR, PodIdx, XHS_VLAN);
    }

    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to add port (ethpod%d.%d) to XHS bridge (%s)\n", PodIdx, XHS_VLAN, XHS_BR);
        return rc;
    }

    if(isOvsMode) {
        rc = v_secure_system("/usr/bin/ovs-vsctl del-port %s ethpod%d.%d", (isPaceXF3 ? LNF_BR_XF3 : LNF_BR), PodIdx, LNF_VLAN);
        rc = v_secure_system("/usr/bin/ovs-vsctl add-port %s ethpod%d.%d", (isPaceXF3 ? LNF_BR_XF3 : LNF_BR), PodIdx, LNF_VLAN);
    } else {
        rc = v_secure_system("brctl addif %s ethpod%d.%d", (isPaceXF3 ? LNF_BR_XF3 : LNF_BR), PodIdx, LNF_VLAN);
    }
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to add port (ethpod%d.%d) to LNF bridge (%s)\n", PodIdx, LNF_VLAN, (isPaceXF3 ? LNF_BR_XF3 : LNF_BR));
        return rc;
    }
#ifdef WAN_FAILOVER_SUPPORTED
  //In case of ethernet gre creation in gateway, we will not be adding
  // vlan 200 gre on brRWAN and hence explicitly we need to create bridge here,

    if (get_eth_interface(ethports))
        MeshInfo("Eth ports are :%s\n", ethports);

    if (get_wan_bridge() && meshWANIfname != NULL)
    {
        MeshInfo("Mesh Wan interface :%s\n", meshWANIfname);
    }
    else
    {
        MeshInfo("Mesh Wan interface name is not set returning\n");
        return 0;
    }

    rc = v_secure_system("ovs-vsctl add-br %s",meshWANIfname);
    rc = v_secure_system("ifconfig %s up",meshWANIfname);
    tok_ethport = strtok_r (ethports, " ",&context);
    while (tok_ethport != NULL){
        rc = v_secure_system("vconfig add %s %d",tok_ethport,MESH_EXTENDER_VLAN);
        rc = v_secure_system("ifconfig %s.%d up",tok_ethport,MESH_EXTENDER_VLAN);
        MeshInfo("Bridge : port %s.%d is added to %s\n",tok_ethport,MESH_EXTENDER_VLAN,meshWANIfname);
        rc = v_secure_system("ovs-vsctl add-port %s %s.%d",meshWANIfname,tok_ethport,MESH_EXTENDER_VLAN);
        tok_ethport = strtok_r(NULL, " ",&context);
    }
#endif
    return 0;
}

static void Mesh_EthPodTunnel(PodTunnel *tunnel)
{
    int rc = -1;
    int PodIdx = Mesh_getIpOctet(tunnel->podaddr, 4);
    bool isOvsMode = access(OVS_ENABLED, F_OK) == 0;

    if(isXB3Platform) {
        MeshInfo("%s Trigger to create tunnel in XB3 platform\n", __FUNCTION__);
        rc= v_secure_system( ETHBHAUL_SWITCH " -gre %d %s", PodIdx, tunnel->podaddr);
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("%s -eb_enable : Ethernet backhaul gre failed = %d\n", ETHBHAUL_SWITCH, WEXITSTATUS(rc));
        }
        return;
    }

    rc = Mesh_CreateEthTunnel(PodIdx, ETHBHAUL_BR_IP, tunnel->podaddr, tunnel->dev, isOvsMode);
    if(rc < 0)
    {
        MeshError("Failed to create Ethernet pod tunnel\n");
        return;
    }

    if(isOvsMode) {
        rc = v_secure_system("/usr/bin/ovs-vsctl add-port %s ethpod%d", MESHBHAUL_BR, PodIdx);
    } else {
        rc = v_secure_system("brctl addif %s ethpod%d", MESHBHAUL_BR, PodIdx);
    }

    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to add ethpod%d to mesh backhaul bridge (%s) with error code: %d\n", PodIdx, MESHBHAUL_BR, rc);
        return;
    }

    rc = Mesh_EthBhaulPodVlanSetup(PodIdx, isOvsMode);
    if(rc < 0)
    {
        MeshError("Failed to setup ethernet backhaul VLAN, error code: %d\n", rc);
        return;
    }

    if( (!isSkyHUB4) && (!gmssClamped) ) {
        MeshInfo("TCP MSS for XHS is enabled \n");
        sysevent_set(sysevent_fd, sysevent_token, "eb_gre", "up", 0);
        sysevent_set(sysevent_fd, sysevent_token, "firewall-restart", NULL, 0);
        gmssClamped = true;
    }
#if defined(WAN_FAILOVER_SUPPORTED)
    char cmd[256]={0};
    snprintf(cmd, sizeof(cmd), "ethpod%d", PodIdx);
    Mesh_backup_network(cmd, MESH_GATEWAY_DEVICE_MODE, true);
#endif
}
/**
 *  @brief Mesh Agent dnsmasq lease server thread
 *  This function will create a server socket for the dnsmasq lease notifications.
 *  dnsmasq sends the lease update related notifications to mesh-agent
 *
 *  @return 0
 */
static void* leaseServer(void *data)
{
   UNREFERENCED_PARAMETER(data);
   errno_t rc=-1;
   int Socket;
   MeshNotify rxBuf;
   int ret = 0;
   memset(&rxBuf, 0, sizeof(MeshNotify));
   struct sockaddr_in serverAddr;
   char atomIP[32] = {0};
   int msgType = 0;
   FILE *cmd = NULL;
   bool gdoNtohl;

   cmd = v_secure_popen("r", "grep ATOM_INTERFACE_IP /etc/device.properties | cut -d '=' -f2");
    if(cmd == NULL) {
       MeshInfo("%s : unable to get the atom IP address",__FUNCTION__);
       return NULL;
    }
   fgets(atomIP, sizeof(atomIP), cmd);
   v_secure_pclose(cmd);

   Socket = socket(PF_INET, SOCK_DGRAM, 0);
   /* Coverity Issue Fix - CID:69541 : Negative Returns */
   if( Socket < 0 )
   {
	MeshError("%s-%d : Error in opening Socket\n" , __FUNCTION__, __LINE__);
	return NULL;
   }
   serverAddr.sin_family = AF_INET;
   if(!isValidIpAddress(atomIP)) {
   //Receive msgs from the dnsmasq
   MeshInfo("leaseServer Socket bind to localhost\n");
   serverAddr.sin_addr.s_addr = inet_addr(LOCAL_HOST);
   serverAddr.sin_port = htons(47040);
   gdoNtohl = false;
   }
   else
   {
   serverAddr.sin_port = htons(47030);
   serverAddr.sin_addr.s_addr = inet_addr(atomIP);
   gdoNtohl = true;
   }
   rc = memset_s(serverAddr.sin_zero, sizeof(serverAddr.sin_zero), '\0', sizeof(serverAddr.sin_zero));
   ERR_CHK(rc);
    /* Coverity Fix CID :57846 CHECKED _RETURN */
   if( bind(Socket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) != 0)
   {
       MeshError("%s-%d : Error in Binding Socket\n" , __FUNCTION__, __LINE__);
       close(Socket);
       return NULL;
   }

   while(1)
   {
     ret = leaseServerRead(Socket, &rxBuf, LS_READ_TIMEOUT_MS);
     if(ret == 0)
     {
         meshHandleTimeout();
         continue;
     }

     if(gdoNtohl)
      msgType = (int)ntohl(rxBuf.msgType);
     else
      msgType = (int)(rxBuf.msgType);
     if(msgType > POD_MAX_MSG)
      Mesh_sendDhcpLeaseUpdate( msgType, rxBuf.lease.mac, rxBuf.lease.ipaddr, rxBuf.lease.hostname, rxBuf.lease.fingerprint);
     else if( msgType == POD_XHS_PORT) {
      MeshWarning("Pod is connected on XHS ethernet Port, Unplug and plug in to different one\n");
      notifyEvent(ERROR, EB_XHS_PORT, rxBuf.eth_msg.pod_mac);
     } else if( msgType == POD_ETH_PORT) {
      if( !g_pMeshAgent->PodEthernetBackhaulEnable) {
        MeshWarning("Pod is non operational on ethernet port while Ethernet bhaul feature is disabled\n");
        notifyEvent(ERROR, EB_RFC_DISABLED, rxBuf.eth_msg.pod_mac);
      }
      else {
        MeshWarning("Potential Dnsmasq and meshAgent sync issue, resync with sending the pod addresses again\n");
        Mesh_SendPodAddresses();
      }
     } else if( msgType == POD_BHAUL_CHANGE)
     {
      MeshInfo("Pod link change detected\n");
      meshHandleEvent(rxBuf.eth_msg.pod_mac, DHCP_ACK_BHAUL_EVENT);
      Mesh_logLinkChange();
     }
     else if( msgType == POD_MAC_POLL)
     {
      MeshInfo("Dnsmasq sent poll to retrieve pod mac addresses\n");
      Mesh_SendPodAddresses();
     }
     else if( msgType == POD_CREATE_TUNNEL)
     {
      MeshInfo("Ethernet pod detected, creating GRE tunnels for the same %s %s %s\n" , rxBuf.tunnel.podmac, rxBuf.tunnel.podaddr, rxBuf.tunnel.dev);
      meshHandleEvent(rxBuf.eth_msg.pod_mac, DHCP_ACK_VLAN_EVENT);
      Mesh_EthPodTunnel(&rxBuf.tunnel);
     }
     else if(msgType == POD_PRIV)
     {
         meshHandleEvent(rxBuf.eth_msg.pod_mac, DHCP_ACK_PRIV_EVENT);
     }
     else
      MeshError("%s : Unknown Msg = %d\n", __FUNCTION__, msgType);
    }

    return NULL;
}

static ssize_t leaseServerRead(int fd, MeshNotify* notify, int timeout)
{
    int ret = 0;
    ssize_t len = 0;
    fd_set read_flags;
    struct timeval tv = {0};

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    FD_ZERO(&read_flags);
    FD_SET(fd, &read_flags);

    ret = select(fd + 1, &read_flags, NULL, NULL, &tv);
    if(ret == 0){
        return 0; 
    }
    else if(ret < 0){
        MeshError("Select socket::error=%s|errno=%d\n", strerror(errno), errno);
        return -2; 
    }

    if (FD_ISSET(fd, &read_flags))
    {
        FD_CLR(fd, &read_flags);

        memset(notify, 0, sizeof(MeshNotify));
        len = recv(fd, (void*)notify, sizeof(MeshNotify), 0);
        if(len <= 0){
            if(len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)){
                MeshInfo("No data received from socket::error=%s|errno=%d\n",
                    strerror(errno), errno);
                return 0; // TODO: Use more meaningful code
            }

            MeshError("Socket fd=%d connection was closed. Len: %zd\n", fd, len);
            return -3; // TODO: Use more meaningful code
        }
    }

    return len;
}

#if defined(ENABLE_MESH_SOCKETS)

/**
 *  @brief Mesh Agent message queue server thread
 *
 *  This function represents the Mesh Agent's server message queue processing loop. Messages will
 *  continue to be processed until the meshAgent is killed. When we receive a message from the mesh
 *  subprocesses, we will convert it into an RDKB format and send it off to the CcspWiFiAgent.
 *
 *  @return 0
 */
static void* msgQServer(void *data)
{
    UNREFERENCED_PARAMETER(data);
    int master_socket, addrlen, new_socket, activity, i, sd;
    int max_sd;
    struct sockaddr_un address;
    errno_t rc=-1;

    MeshSync rxMsg = {0}; //received message

    //set of socket descriptors
    fd_set readfds;

    //create a master socket
    if( (master_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        MeshError("Mesh Queue socket creation failure\n");
        return NULL;
    }

    //type of socket created
    rc = memset_s(&address, sizeof(address), 0, sizeof(address));
    ERR_CHK(rc);
    address.sun_family = AF_UNIX;

    if (*meshSocketPath == '\0') {
      *address.sun_path = '\0';
      rc = strcpy_s(address.sun_path+1, sizeof(address.sun_path)-1, meshSocketPath+1);
      if(rc != EOK)
      {
          ERR_CHK(rc);
          MeshError("Error in copying meshSocketPath\n");
          close(master_socket);
          return NULL;
      }
    } else {
      rc = strcpy_s(address.sun_path, sizeof(address.sun_path), meshSocketPath);
      if(rc != EOK)
      {
          ERR_CHK(rc);
          MeshError("Error in copying meshSocketPath to address.sun_path\n");
          close(master_socket);
          return NULL;
      }
      unlink(meshSocketPath);
    }

    //bind the socket
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)
    {
       /* Coverity  Fix CID:54336 RESOURCE_LEAK */
        close(master_socket);
        MeshError("Mesh Queue socket bind failure\n");
        return NULL;
    }

    //try to specify maximum MAX_CONNECTED_CLIENTS pending connections for the master socket
    if (listen(master_socket, MAX_CONNECTED_CLIENTS) < 0)
    {
        MeshError("Mesh Queue socket listen failure\n");
        return NULL;
    }

    //accept the incoming connection
    addrlen = sizeof(address);
    MeshInfo("Waiting for connections ...\n");

    while(TRUE)
    {
        //clear the socket set
        FD_ZERO(&readfds);

        //add master socket to set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        //add child sockets to set
        for ( i = 0 ; i < MAX_CONNECTED_CLIENTS ; i++)
        {
            //socket descriptor
            sd = clientSockets[i];

            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET( sd , &readfds);

            //highest file descriptor number, need it for the select function
            if(sd > max_sd)
                max_sd = sd;
        }

        //wait for an activity on one of the sockets , timeout is NULL ,
        //so wait indefinitely
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);

        if ((activity < 0) && (errno!=EINTR))
        {
            MeshError("Mesh Queue select error %d\n", errno);
        }

        //If something happened on the master socket ,
        //then its an incoming connection
        if (FD_ISSET(master_socket, &readfds))
        {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
            {
                MeshError("Mesh Queue accept failure\n");
                return NULL;
            }
            //inform user of socket number - used in send and receive commands
            MeshInfo("New Mesh Queue connection, socket fd is %d\n", new_socket);

            //add new socket to array of sockets
            for (i = 0; i < MAX_CONNECTED_CLIENTS; i++)
            {
                //if position is empty
                if( clientSockets[i] == 0 )
                {
                    clientSockets[i] = new_socket;
                    //Maintain a bitfield to see if any connected
                    clientSocketsMask |= (1 << i);
                    MeshInfo("Adding connected client to list of sockets as %d\n" , i);
                    Mesh_sendDhcpLeaseSync();
                    Mesh_sendRFCUpdate("PodEthernetGreBackhaul.Enable", "true", rfc_boolean);
                    break;
                }
            }
        }

        // Wait here until the Mesh_sysevent_handler process is ready to accept messages. This is
        // required in the event that the MeshService (Plume) is already running. We don't want to
        // miss any messages. If the SysEventhandler never comes online, we're doomed anyway.
        while (!s_SysEventHandler_ready) {
            sleep(5);
        }

        // Check for I/O operations on client sockets
        for (i = 0; i < MAX_CONNECTED_CLIENTS; i++)
        {
            sd = clientSockets[i];

            if (FD_ISSET( sd , &readfds))
            {
                // clear out the rx buffer before reading
                rc = memset_s((void *)&rxMsg, sizeof(MeshSync), 0, sizeof(MeshSync));
                ERR_CHK(rc);

                //Check if it was for closing, and also read the
                //incoming message
                if (read(sd, (void *) &rxMsg, sizeof(MeshSync)) == 0)
                {
                    //Somebody disconnected , get his details and print
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    MeshInfo("Client disconnected fd %d\n", sd);

                    //Close the socket and mark as available in list for reuse
                    close(sd);
                    clientSockets[i] = 0;
                    //Unmask the bit for connected client
                    clientSocketsMask &= ~(1 << i);
                }
                else
                {
                    // Process the received message
                    Mesh_ProcessSyncMessage(rxMsg);
                }
            }
        }
    }

    return 0;
}

/**
 *  @brief Mesh Agent send to client
 *
 *  This function will send a message to the connected clients
 *
 *  @return 0
 */
static int msgQSend(MeshSync *data)
{
    int i, ret = 0;

    for (i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        int sd = clientSockets[i];

        /* send the message */
        if (sd != 0) {
            if (send(sd, (char *)data, sizeof(MeshSync), 0) == -1)
            {
                MeshError("Error %d sending to client message socket %d\n",errno, sd);
                //Close the socket and mark as available in list for reuse
                close(sd);
                clientSockets[i] = 0;
                clientSocketsMask &= ~(1 << i);
           }
           else
               ret = 1;
        }
    }

    return ret;
}
#else
/**
 *  @brief Mesh Agent message queue server thread
 *
 *  This function represents the Mesh Agent's server message queue processing loop. Messages will
 *  continue to be processed until the meshAgent is killed. When we receive a message from the mesh
 *  subprocesses, we will convert it into an RDKB format and send it off to the CcspWiFiAgent.
 *
 *  @return 0
 */
static void* msgQServer(void *data)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    // Start message queue server (communications to mesh processes)
    struct mq_attr qAttr, qAttr_old;
    MeshSync rxMsg = {0};
    unsigned int prio;
    errno_t rc=-1;

    qAttr.mq_flags = 0;
    qAttr.mq_maxmsg = MAX_MESSAGES;
    qAttr.mq_msgsize = sizeof(MeshSync);
    qAttr.mq_curmsgs = 0;

    if ((qd_server = mq_open (MESH_SERVER_QUEUE_NAME, O_RDONLY | O_CREAT, QUEUE_PERMISSIONS, &qAttr)) == -1) {
        // perror ("Server: mq_open (server)");
        MeshError(("Error %d creating server message queue %s\n", errno, MESH_SERVER_QUEUE_NAME));
        return errno;
    }

    // Get the attributes for the server message queue
    mq_getattr (qd_server, &qAttr);
    MeshInfo("%d messages are currently in the server queue\n", qAttr.mq_curmsgs);

    // Eat any previous messages in the queue
    if (qAttr.mq_curmsgs != 0) {

      // First set the queue to not block any calls
      qAttr.mq_flags = O_NONBLOCK;
      mq_setattr (qd_server, &qAttr, &qAttr_old);

      // Eat all of the old messages
      while (mq_receive (qd_server, (char *) &rxMsg, sizeof(MeshSync), &prio) != -1)
        MeshInfo ("Received a message with priority %d.\n", prio);

      // The call failed.  Make sure errno is EAGAIN
      if (errno != EAGAIN) {
        MeshError(("Error %d reading messages from %s\n", errno, MESH_SERVER_QUEUE_NAME));
        return errno;
      }

      // Now restore the attributes
      mq_setattr (qd_server, &qAttr_old, 0);
    }

    // Wait here until the Mesh_sysevent_handler process is ready to accept messages. This is
    // required in the event that the MeshService (Plume) is already running. We don't want to
    // miss any messages. If the SysEventHandler never comes online, we're doomed anyway.
    while (!s_SysEventHandler_ready) {
        sleep(5);
    }

    for (;;)
    {
        // clear out the rx buffer before reading
        rc = memset_s((void *)&rxMsg, sizeof(MeshSync), 0, sizeof(MeshSync));
        ERR_CHK(rc);

        // get the oldest message with highest priority
        if (mq_receive (qd_server, (char *) &rxMsg, sizeof(MeshSync), NULL) == -1) {
            // perror ("Server: mq_receive");
            MeshError("Error %d receiving message from queue %s\n", errno, MESH_SERVER_QUEUE_NAME);
            break; // kick out of loop and clean up
        }

        // Process the received message
        Mesh_ProcessSyncMessage(rxMsg);
    }

    // Tear down the message queue
    mq_close(qd_server);
    mq_unlink(MESH_SERVER_QUEUE_NAME);

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return 0;
}


/**
 *  @brief Mesh Agent send to client
 *
 *  This function will send a message to the client message queue
 *
 *  @return 0
 */
static int msgQSend(MeshSync *data)
{
    mqd_t qd_client;
    struct mq_attr attr;

    if ((qd_client = mq_open (MESH_CLIENT_QUEUE_NAME, O_WRONLY)) == -1) {
        //MeshError("Error %d connecting to client msgQueue %s\n", errno, MESH_CLIENT_QUEUE_NAME);
        return errno;
    }

    // Get the attributes for the client message queue
    mq_getattr (qd_client, &attr);
    if (attr.mq_curmsgs > 0) {
        MeshInfo("%d messages are currently in the client queue\n", attr.mq_curmsgs);
    }

    /* send the message */
    if (mq_send(qd_client, (char *)data, sizeof(MeshSync), 0) == -1)
    {
        MeshError("Error %d sending to client msgQueue %s\n",errno, MESH_CLIENT_QUEUE_NAME);
    }

       /* cleanup */
    if (mq_close(qd_client) == -1)
    {
        MeshError("Error %d closing msgQueue to client\n", errno);
    }

    return 0;
}
#endif

/**
 * @brief Mesh Agent Get Url
 *
 * This function will get the url
 */
int Mesh_GetUrl(char *retBuf, int bufSz)
{
    errno_t rc = -1;

    // MeshInfo("Entering into %s\n",__FUNCTION__);
    /*CID 377534  Calling Mesh_SysCfgGetStr without checking return value (as is done elsewhere 17 out of 18 times).*/
    if (Mesh_SysCfgGetStr("mesh_url", retBuf, bufSz) != 0)
    {
        
        MeshError("Error in retrieving mesh_url\n");
        return false;
    }
    

    if (retBuf[0] == 0)
    {
        // syscfg value is blank, send url default value
        rc = strcpy_s(retBuf, bufSz, urlDefault);
        if(rc != EOK)
        {
           ERR_CHK(rc);
           MeshError("Error in copying url default value\n");
           return false;
        }
    }

    return true;
}

/**
 * @brief Mesh Agent Set Url
 *
 * This function will set the url and notify the Mesh vendor of the change
 */
bool Mesh_SetUrl(char *url, bool init)
{
    unsigned char outBuf[128] = {0};
    errno_t rc       = -1;
    int     ind      = -1;
    bool success = TRUE;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    Mesh_GetUrl(outBuf, sizeof(outBuf));
    // If the url value is different, set the syscfg value and notify the mesh vendor
    rc = strcmp_s(url,strlen(url),outBuf,&ind);
    ERR_CHK(rc);
    if (init || ((rc == EOK) && (ind != 0)))
    {
        // Update the data model
        rc = strcpy_s(g_pMeshAgent->meshUrl, sizeof(g_pMeshAgent->meshUrl), url);
        if(rc != EOK)
        {
           ERR_CHK(rc);
           MeshError("Error in copying url to data model g_pMeshAgent->meshUrl\n");
           return FALSE;
        }
        MeshSync mMsg = {0};
        // update the syscfg database
        Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, url, false);
        // Notify plume
        // Set sync message type
        mMsg.msgType = MESH_URL_CHANGE;
        rc = strcpy_s(mMsg.data.url.url, sizeof(mMsg.data.url.url), url);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            MeshError("Error in copying url to mMsg.data.url.url\n");
            return FALSE;
        }
        // We filled our data structure so we can send it off
        msgQSend(&mMsg);

        MeshInfo("Meshwifi URL is set to %s\n", g_pMeshAgent->meshUrl);

        // Send sysevent notification
        /* Coverity Fix CID:66684 DC.STRING_BUFFER */
        snprintf(outBuf,sizeof(outBuf), "MESH|%s", url);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, outBuf, 0, false);
    }

    return success;
}

/**
 * @brief Mesh Agent Get State
 *
 * This function will return the mesh state
 */
eMeshStateType Mesh_GetMeshState()
{
    unsigned char out_val[128];
    errno_t rc       = -1;
    int     ind      = -1;
    eMeshStateType state = MESH_STATE_FULL;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, out_val, sizeof(out_val)) == 0)
    {
        rc = strcmp_s(meshStateArr[MESH_STATE_MONITOR].mStr,strlen(meshStateArr[MESH_STATE_MONITOR].mStr),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
            state = MESH_STATE_MONITOR;
        }
    }

    return state;
}


/**
 * @brief Mesh Agent Set State
 *
 * This function will set the mesh state and notify the mesh components
 */
bool Mesh_SetMeshState(eMeshStateType state, bool init, bool commit)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    unsigned char outBuf[128];
    MeshSync mMsg = {0};
    bool success = TRUE;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    // If the state value is different or this is during setup - make it happen.
    if (init || Mesh_GetMeshState() != state)
    {
        MeshInfo("Meshwifi state is set to %s\n", meshStateArr[state].mStr);
        // Update the data model
        g_pMeshAgent->meshState = state;

        if(commit)
        {
         /* Coverity Fix CID:55887 CHECKED_RETURN */
         if( Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, meshStateArr[state].mStr, true) != ANSC_STATUS_SUCCESS )
            MeshError(" %s-%d Failed in  Mesh_SysCfgSetStr()\n",__FUNCTION__,__LINE__);
        }
        // Notify plume
        // Set sync message type
        mMsg.msgType = MESH_STATE_CHANGE;
        mMsg.data.meshState.state = state;

        // We filled our data structure so we can send it off
        msgQSend(&mMsg);

        // Send sysevent notification
        /* Coverity Fix CID: 71888 DC.STRING_BUFFER */
        snprintf(outBuf,sizeof(outBuf), "MESH|%s", meshStateArr[state].mStr);
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, outBuf, 0, true);
    }

    return success;
}

/**
 * @brief Mesh Agent Get Enable/Disable
 *
 * This function will return whther or not the mesh service is enabled
 */
bool Mesh_GetEnabled(const char *name)
{
    unsigned char out_val[128];
    errno_t rc       = -1;
    int     ind      = -1;
    bool enabled = false;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(name, out_val, sizeof(out_val)) == 0)
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
            enabled = true;
        }
    }

    return enabled;
}

bool Mesh_GetEnabled_State(const char *name)
{
    unsigned char out_val[128];
    errno_t rc       = -1;
    int     ind      = -1;
    bool enabled = false;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(name, out_val, sizeof(out_val)) == 0)
    {
        rc = strcmp_s("1",strlen("1"),out_val,&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
            enabled = true;
        }
    }

    return enabled;
}

bool Mesh_GetSecureBackhaul_Enable(const char *name)
{
    unsigned char out_val[128];
    errno_t rc       = -1;
    int     ind      = -1;
    bool enabled = false;

    // MeshInfo("Entering into %s\n",__FUNCTION__);

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(name, out_val, sizeof(out_val)) == 0)
    {
        rc = strcmp_s("1",strlen("1"),out_val,&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
            enabled = true;
        }
    }

    return enabled;
}

static void changeChBandwidth(int radioId, int channelBw)
{
  CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
  parameterValStruct_t   param_val[1];
  char parameterName[256];
  char parameterValue[16];
  char *component = "eRT.com.cisco.spvtg.ccsp.wifi";
  char *bus = "/com/cisco/spvtg/ccsp/wifi";
  char* faultParam      = NULL;
  int   ret             = 0;

  sprintf(parameterName, "Device.WiFi.Radio.%d.OperatingChannelBandwidth", radioId+1);
  sprintf(parameterValue, "%dMHz", channelBw);

  param_val[0].parameterName=parameterName;
  param_val[0].parameterValue=parameterValue;
  param_val[0].type = ccsp_string;

  MeshInfo("RDK_LOG_WARN, %s-%d [set %s %s] \n",__FUNCTION__,__LINE__, parameterName, parameterValue);

    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            bus,
            0,
            0,
            param_val,
            1,
            TRUE,
            &faultParam
            );

    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) {
        MeshError(" %s-%d Failed to set %s\n",__FUNCTION__,__LINE__, parameterName);
        bus_info->freefunc( faultParam );
    }
}

BOOL set_wifi_boolean_enable(char *parameterName, char *parameterValue)
{
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t   param_val[1];
    char *component = "eRT.com.cisco.spvtg.ccsp.wifi";
    char *bus = "/com/cisco/spvtg/ccsp/wifi";
    char* faultParam      = NULL;
    int   ret             = 0;

    param_val[0].parameterName=parameterName;
    param_val[0].parameterValue=parameterValue;
    param_val[0].type = ccsp_boolean;

    MeshInfo("RDK_LOG_WARN, %s-%d [set %s %s] \n",__FUNCTION__,__LINE__, parameterName, parameterValue);

    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            bus,
            0,
            0,
            param_val,
            1,
            TRUE,
            &faultParam
            );

    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) {
        MeshError(" %s-%d Failed to set %s\n",__FUNCTION__,__LINE__, parameterName);
        bus_info->freefunc( faultParam );
        return FALSE;
    }
    return TRUE;
}

static BOOL is_configure_wifi_enabled(void)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char *dstComponent = "eRT.com.cisco.spvtg.ccsp.pam";
    char *dstPath = "/com/cisco/spvtg/ccsp/pam";
    char *paramNames[]={"Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi"};
    int  valNum = 0;
    errno_t rc = -1;
    int ind = -1;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            1,
            &valNum,
            &valStructs);

    if (CCSP_Message_Bus_OK != ret)
    {
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    MeshWarning("valStructs[0]->parameterValue = %s\n",valStructs[0]->parameterValue);

    rc = strcmp_s("true",strlen("true"),valStructs[0]->parameterValue,&ind);
    ERR_CHK(rc);
    if ((ind == 0) && (rc == EOK))
    {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return TRUE;
    }
    else
    {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return FALSE;
    }
}

static BOOL is_band_steering_enabled(void)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char *dstComponent = "eRT.com.cisco.spvtg.ccsp.wifi";
    char *dstPath = "/com/cisco/spvtg/ccsp/wifi";
    char *paramNames[]={"Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable"};
    int  valNum = 0;
    errno_t rc = -1;
    int ind = -1;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            1,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret)
    {
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    MeshWarning("valStructs[0]->parameterValue = %s\n",valStructs[0]->parameterValue);

    rc = strcmp_s("true",strlen("true"),valStructs[0]->parameterValue,&ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))   {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return TRUE;
    }
    else
    {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return FALSE;
    }
}

#if 0
static BOOL is_reset_needed(void)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char *dstComponent = "eRT.com.cisco.spvtg.ccsp.wifi";
    char *dstPath = "/com/cisco/spvtg/ccsp/wifi";
    char *paramNames[]={"Device.WiFi.SSID.13.Enable", "Device.WiFi.SSID.14.Enable"};
    int  valNum = 0;
    BOOL ret_b=FALSE;
    errno_t rc[2] = {-1, -1};
    int ind[2] = {-1, -1};

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    if(valStructs)
    {
	rc[0] = strcmp_s("true",strlen("true"),valStructs[0]->parameterValue,&ind[0]);
        ERR_CHK(rc[0]);
        rc[1] = strcmp_s("true",strlen("true"),valStructs[1]->parameterValue,&ind[1]);
        ERR_CHK(rc[1]);
	if (((ind[0] == 0 ) && (rc[0] == EOK)) || ((ind[1] == 0) && (rc[1] == EOK)))
	{
            MeshInfo("Mesh interfaces are up, Need to disable them\n");
            t2_event_d("WIFI_INFO_MeshDisabled_syscfg0", 1);
            ret_b=(valStructs?true:false);
	}
    }

    if(valStructs)
     MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return ret_b;
}
#endif

//Enables/Disables Mesh APs, If enable, sets ath12 and ath13 and does apply wifi setting, when mesh
//Disabled , it bring downs Vaps
static void set_mesh_APs(bool enable)
{
 MeshInfo("%s Performing a mesh AP = %s\n",__FUNCTION__,(enable?"true":"false"));
 if(set_wifi_boolean_enable("Device.WiFi.SSID.13.Enable",(enable?"true":"false")))
  MeshInfo("Device.WiFi.SSID.13.Enable succesfully set to %s\n",(enable?"true":"false"));
 if(set_wifi_boolean_enable("Device.WiFi.SSID.14.Enable",(enable?"true":"false")))
  MeshInfo("Device.WiFi.SSID.14.Enable succesfully set to %s\n",(enable?"true":"false"));
}

static BOOL is_SSID_enabled(void)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char *dstComponent = "eRT.com.cisco.spvtg.ccsp.wifi";
    char *dstPath = "/com/cisco/spvtg/ccsp/wifi";
    char *paramNames[]={"Device.WiFi.SSID.13.Status" , "Device.WiFi.SSID.14.Status"};
    int  valNum = 0;
    BOOL ret_b=FALSE;
    errno_t rc = -1;
    int ind = -1;
    int ifaceDown = 0;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    if(valStructs)
    {
	rc = strcmp_s("Down",strlen("Down"),valStructs[0]->parameterValue,&ind);
        ERR_CHK(rc);
	if((ind ==0 ) && (rc == EOK)) 
	{
	     ifaceDown = 1;
	}
	else 
	{
	     rc = strcmp_s("Down",strlen("Down"),valStructs[1]->parameterValue,&ind);
             ERR_CHK(rc);
	     if((ind ==0 ) && (rc == EOK)) 
	     {
		   ifaceDown = 1;
	     }
	}
    }
	
	if(ifaceDown)
        MeshInfo("Mesh interfaces are Down \n");
    else
         ret_b=(valStructs?true:false);

    if(valStructs)
     MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return ret_b;
}

static void is_xf3_xb3_platform(void)
{
    FILE *cmd;
    char platform[32] = {'\0'};

    cmd = v_secure_popen("r","grep BOX_TYPE /etc/device.properties | cut -d '=' -f2");
    if(cmd == NULL) {
        MeshInfo("Mesh BOX_TYPE fetch failed \n");
        return;
    }
    fgets(platform, sizeof(platform), cmd);
    v_secure_pclose(cmd);
    platform[strlen(platform) -1] = '\0';
    if (strncmp(XF3_PLATFORM,platform, sizeof(XF3_PLATFORM)) == 0) {
        isPaceXF3 = true;
    } else if (strncmp(XB3_PLATFORM, platform, sizeof(XB3_PLATFORM)) == 0) {
        isXB3Platform = true;
    } else if (strncmp(HUB4_PLATFORM, platform, sizeof(HUB4_PLATFORM)) == 0) {
        isSkyHUB4 = true;
    } else if (strncmp(CBR2_PLATFORM, platform, sizeof(CBR2_PLATFORM)) == 0) {
        isCBR2 = true;
    }
    MeshInfo("platform check XF3:%d, XB3:%d HUB4:%d CBR2:%d\n",
                    isPaceXF3, isXB3Platform, isSkyHUB4, isCBR2);
}

static BOOL radio_check(void)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char *dstComponent = "eRT.com.cisco.spvtg.ccsp.wifi";
    char *dstPath = "/com/cisco/spvtg/ccsp/wifi";
    int  valNum = 0;
    BOOL ret_b=FALSE;
    int ind = -1;
    errno_t rc = -1;
    int radioDown = 0;
    char *radio1 = isPaceXF3 ? RADIO_ENABLE_24 : RADIO_STATUS_24;
    char *radio2 = isPaceXF3 ? RADIO_ENABLE_50 : RADIO_STATUS_50;
    char *state = isPaceXF3 ? STATE_FALSE : STATE_DOWN;
    char *paramNames[]={radio1,radio2};

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    if(valStructs)
    {
            rc = strcmp_s(state,strlen(state),valStructs[0]->parameterValue,&ind);
            ERR_CHK(rc);
            if ((ind ==0 ) && (rc == EOK)) 
            {
                radioDown = 1;
            }
            else
            {
                rc = strcmp_s(state,strlen(state),valStructs[1]->parameterValue,&ind);
                ERR_CHK(rc);
                if ((ind ==0 ) && (rc == EOK)) 
		{
		    radioDown = 1;
		}
			
	    }
	
    }
	
    if(radioDown)
        MeshError("Radio Error: Status 2.4= %s 5= %s \n", valStructs[0]->parameterValue, valStructs[1]->parameterValue);
    else
         ret_b=(valStructs?true:false);

    if(valStructs)
     MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    if(!ret_b) {
      MeshError(("MESH_ERROR:Fail to enable Mesh because either one of the radios are off\n"));
      t2_event_d("WIFI_ERROR_MESH_FAILED", 1);
    }

    return ret_b;
}

#ifdef WAN_FAILOVER_SUPPORTED
bool
get_wan_bridge()
{
    char *val = NULL;
    int ret = true;
    int len = 0;

    if (meshWANIfname == NULL)
    {
        meshWANIfname = (char *) malloc(MAX_IFNAME_LEN);

        memset(meshWANIfname, '\0',MAX_IFNAME_LEN);

        if (PSM_Get_Record_Value2(bus_handle, g_Subsystem,
                    MESH_WAN_INTERFACE, NULL, &val) == CCSP_SUCCESS)
        {
            if(val)
            {
                len = strlen(val);
                if(len > 0)
                {
                    snprintf(meshWANIfname, MAX_IFNAME_LEN, "%s", val);
                    ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(val);
                }
                else
                {
                    MeshError(("MESH_ERROR:PSM_Get_Record_Value2 return empty\n"));
                    free(meshWANIfname);
                    meshWANIfname = NULL;
                    ret = false;
                }
            }
            else
               ret = false;
        }
        else
            ret = false;
    }
    return ret;
}

bool
get_eth_interface(char * eth_interface)
{
    char *val = NULL;
    int ret = false;
    int len = 0;

    if (eth_interface == NULL)
    {
        MeshError(("eth_interface = NULL\n"));
        return false;
    }

    if (PSM_Get_Record_Value2(bus_handle, g_Subsystem,
                MESH_ETH_INTERFACE, NULL, &val) == CCSP_SUCCESS)
    {
        if(val) {
            len = strlen(val);
            if(len > 0)
            {
                snprintf(eth_interface, ETH_IFNAME_MAX_LEN, "%s", val);
                ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(val);
                ret = true;
            }
        }
    }
    return ret;
}
#endif

BOOL is_bridge_mode_enabled()
{
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.pam";
    char dstPath[64]="/com/cisco/spvtg/ccsp/pam";
    char *paramNames[]={"Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode"};
    int  valNum = 0;
    errno_t rc[2] = {-1, -1};
    int ind[2] = {-1, -1};

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            1,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret)
    {
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %lu\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    MeshWarning("valStructs[0]->parameterValue = %s\n",valStructs[0]->parameterValue);

    rc[0] = strcmp_s("bridge-static",strlen("bridge-static"),valStructs[0]->parameterValue,&ind[0]);
    ERR_CHK(rc[0]);
    rc[1] = strcmp_s("full-bridge-static",strlen("full-bridge-static"),valStructs[0]->parameterValue,&ind[1]);
    ERR_CHK(rc[1]);
    if(((ind[0] == 0 ) && (rc[0] == EOK)) || ((ind[1] == 0) && (rc[1] == EOK)))
    {
         MeshError("Brigde mode enabled, setting mesh wifi to disabled \n");
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return TRUE;
    }
    else
    {
        free_parameterValStruct_t(bus_handle, valNum, valStructs);
        return FALSE;
    }

}

static bool Mesh_getPartnerBasedURL(char *url)
{
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char *dstComponent = "eRT.com.cisco.spvtg.ccsp.pam";
    char *dstPath = "/com/cisco/spvtg/ccsp/pam";
    char *paramNames[]={PARTNER_REDIRECTORURL_PARAMNAME};
    int  valNum = 0;
    MeshInfo("Fetching the Redirector URL based on partnerID\n");

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            1,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret)
    {
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %lu\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return false;
    }
    if(strlen(valStructs[0]->parameterValue) > 0)
    {
        strcpy(url,valStructs[0]->parameterValue);
        MeshInfo("%s Returned URL for the partner = %s\n",__FUNCTION__, url);
        return true;
    }
    else
    {
        MeshError("%s Empty URL, go with defaults\n", __FUNCTION__); 
        return false;
    }
}

static bool  meshSetSyscfgBool(bool enable,eMeshSyncType type)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting %s in syscfg to %d\n", __FUNCTION__, meshSyncMsgArr[type].sysStr,enable);
    if(Mesh_SysCfgSetStr(meshSyncMsgArr[type].sysStr, (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set %s in syscfg, retrying 5 times\n",meshSyncMsgArr[type].sysStr);
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr(meshSyncMsgArr[type].sysStr, (enable?"true":"false"), true))
            {
                MeshInfo("%s syscfg set to %s passed in %d attempt\n",meshSyncMsgArr[type].sysStr,(enable?"true":"false"),i+1);
                success = true;
                break;
            }
            else
            {
                MeshInfo("%s syscfg set retrial failed in %d attempt\n",meshSyncMsgArr[type].sysStr,i+1);
            }
        }
    }
    else
    {
        MeshInfo("%s set to %s in the syscfg is success\n",meshSyncMsgArr[type].sysStr,(enable?"true":"false"));
        success = true;
    }

    return success;
}

static void Mesh_setCacheStatusSyscfg(bool enable)
{
    int i = 0;

    MeshInfo("%s: Trying to set mesh_cache syscfg to [%s]\n", __FUNCTION__, enable ? "true" : "false");
    for (i = 0; i < 5; i++)
    {
        if (!Mesh_SysCfgSetStr("mesh_cache", (enable ? "true" : "false"), true))
        {
            MeshInfo("mesh_cache syscfg set passed in %d attempt\n", i+1);
            break;
        }
    }
}

static void Mesh_setSecuritySchemaLegacySyscfg(bool enable)
{
    int i = 0;

    MeshInfo("%s: Trying to set  syscfg to [%s]\n", __FUNCTION__, enable ? "true" : "false");
    for (i = 0; i < 5; i++)
    {
        if (!Mesh_SysCfgSetStr("mesh_security_legacy", (enable ? "true" : "false"), true))
        {
            MeshInfo("mesh_security_legacy syscfg set passed in %d attempt\n", i+1);
            break;
        }
    }
}

static bool meshSetMeshRetrySyscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting Optimized Mesh Retry enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_REDUCED_RETRY].sysStr, (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the Optimized Mesh Retry Enable in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_REDUCED_RETRY].sysStr, (enable?"true":"false"), true))
            {
                MeshInfo("Optimized Mesh Retry syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
            }
            else
            {
                MeshInfo("Optimized Mesh Retry syscfg set retrial failed in %d attempt\n", i+1);
            }
        }
    }
    else
    {
        MeshInfo("Optimized Mesh Retry enable set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

static bool meshwifiMotionSyscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting wifi motion in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_WIFI_MOTION].sysStr, (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set wifi motion in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_WIFI_MOTION].sysStr, (enable?"true":"false"), true))
            {
                MeshInfo("wifi motion syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
            }
            else
            {
                MeshInfo("wifi motion syscfg set retrial failed in %d attempt\n", i+1);
            }
        }
    }
    else
    {
        MeshInfo("wifi motion enable set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

static void meshSetEthbhaulSyscfg(bool enable)
{
    int i =0;

    MeshInfo("%s Setting eth bhaul enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr, (enable?"true":"false"), true) != 0) {
         MeshInfo("Failed to set the Eth Bhaul Enable in syscfg, retrying 5 times\n");
         for(i=0; i<5; i++) {
         if(!Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr, (enable?"true":"false"), true)) {
           MeshInfo("eth bhaul syscfg set passed in %d attempt\n", i+1);
           break;
         }
         else
          MeshInfo("eth bhaul syscfg set retrial failed in %d attempt\n", i+1);
      }
   }
   else
    MeshInfo("eth bhaul enable set in the syscfg successfully\n");
}

#ifdef ONEWIFI
static void meshSetXleModeCloudCtrlEnableSyscfg(bool enable)
{
    int i =0;

    MeshInfo("%s Setting xle mode cloud control flag enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_XLE_MODE_CLOUD_CTRL_RFC].sysStr, (enable?"true":"false"), true) != 0) {
         MeshInfo("Failed to set the xle mode cloud control flag in syscfg, retrying 5 times\n");
         for(i=0; i<5; i++) {
         if(!Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_XLE_MODE_CLOUD_CTRL_RFC].sysStr, (enable?"true":"false"), true)) {
           MeshInfo("xlw mode cloud control flag syscfg set passed in %d attempt\n", i+1);
           break;
         }
         else
          MeshInfo("xle mode cloud control flag syscfg set retrial failed in %d attempt\n", i+1);
      }
   }
   else
    MeshInfo("xle mode cloud control flag set in the syscfg successfully\n");
}
#endif

static bool meshSetGreAccSyscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting GRE_ACC enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("mesh_gre_acc_enable", (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the GRE_ACC Enable in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr("mesh_gre_acc_enable", (enable?"true":"false"), true))
            {
                MeshInfo("GRE_ACC syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
             }
             else
             {
                 MeshInfo("GRE_ACC syscfg set retrial failed in %d attempt\n", i+1);
             }
        }
    }
    else
    {
        MeshInfo("GRE_ACC enable set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

static bool meshSetOVSSyscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting OVS enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("mesh_ovs_enable", (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the OVS Enable in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr("mesh_ovs_enable", (enable?"true":"false"), true))
            {
                MeshInfo("ovs syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
            }
            else
            {
                MeshInfo("ovs syscfg set retrial failed in %d attempt\n", i+1);
            }
        }
    }
    else
    {
        MeshInfo("ovs enable set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

static bool meshSet_sm_app_Syscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting SMAPP disable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("sm_app_disable", (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the SMAPP disable in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr("sm_app_disable", (enable?"true":"false"), true))
            {
                MeshInfo("SMAPP syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
            }
            else
            {
                MeshInfo("SMAPP syscfg set retrial failed in %d attempt\n", i+1);
            }
        }
    }
    else
    {
        MeshInfo("SMAPP disable set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

static bool meshSet_XleAdaptiveFh_Syscfg(bool enable)
{
    int i = 0;
    bool success = false;

    MeshInfo("%s Setting XleAdaptiveFh_State in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("XleAdaptiveFh_State", (enable?"1":"0"), true) != 0)
    {
        MeshInfo("Failed to set the XleAdaptiveFh_State in syscfg, retrying 5 times\n");
        for(i=0; i<5; i++)
        {
            if(!Mesh_SysCfgSetStr("XleAdaptiveFh_State", (enable?"1":"0"), true))
            {
                MeshInfo("XleAdaptiveFh_State syscfg set passed in %d attempt\n", i+1);
                success = true;
                break;
            }
            else
            {
                MeshInfo("XleAdaptiveFh_State syscfg set retrial failed in %d attempt\n", i+1);
            }
        }
    }
    else
    {
        MeshInfo("XleAdaptiveFh_State set in the syscfg successfully\n");
        success = true;
    }

    return success;
}

static bool meshSet_SecureBackhaul_Syscfg(bool enable)
{
    bool success = false;

    MeshInfo("%s Setting SecureBackhaul_Enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("SecureBackhaul_Enable", (enable?"1":"0"), true) != 0)
    {
        MeshInfo("Failed to set the SecureBackhaul_Enable in syscfg\n");
    }
    else
    {
        MeshInfo("SecureBackhaul_Enable set in the syscfg successfully\n");
        success = true;
    }
    return success;
}

bool meshSet_HCMUploadEnable_syscfg(bool enable)
{
    MeshInfo("%s Setting hcm_recording_upload_enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("hcm_recording_upload_enable", (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the hcm_recording_upload_enable in syscfg\n");
        return false;
    }
    MeshInfo("hcm_recording_upload_enable set in the syscfg successfully\n");
    return true;
}

bool meshSet_HDRecommendation_Syscfg(bool enable)
{
    bool success = false;
    MeshInfo("%s Setting mesh_hd_recommendation_enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("mesh_hd_recommendation_enable", (enable?"true":"false"), true) != 0)
    {
        MeshInfo("Failed to set the mesh_hd_recommendation_enable in syscfg\n");
    }
    else
    {
        MeshInfo("mesh_hd_recommendation_enable set in the syscfg successfully\n");
        success = true;
    }
    return success;
}

static bool OpensyncSetSyscfg(bool enable)
{
    int i =0;
    bool success = false;
    MeshInfo("%s Setting Opensync enable in syscfg to %d\n", __FUNCTION__, enable);
    if(Mesh_SysCfgSetStr("opensync", (enable?"true":"false"), true) != 0) {
         MeshInfo("Failed to set the Opensync Enable in syscfg, retrying 5 times\n");
         for(i=0; i<5; i++) {
         if(!Mesh_SysCfgSetStr("opensync", (enable?"true":"false"), true)) {
           MeshInfo("opensync syscfg set passed in %d attempt\n", i+1);
	   success = true;
           break;
         }
         else
          MeshInfo("opensync syscfg set retrial failed in %d attempt\n", i+1);
      }
   }
   else {
    MeshInfo("opensync enable set in the syscfg successfully\n");
    success = true;
   }
//Also restore the older syscfg parameter to match the new one
    if(!enable){
        if(Mesh_SysCfgSetStr("opensync_enable", "false", true) != 0) {
            MeshInfo("Failed to disable the Legacy Opensync Enable in syscfg\n");
        }
        else {
            MeshInfo("legacy opensync enable disabled in the syscfg successfully\n");
        }
    }
   return success;
}

void meshSetSyscfg(bool enable, bool commitSyscfg)
{
    int i =0;
    FILE *fpMeshFile = NULL;
#ifdef RDKB_EXTENDER_ENABLED
   if(!enable)
   {
       MeshInfo("%s Mesh must be enabled always in the extender device\n",__FUNCTION__);
       enable = true;
   }
#endif
    MeshInfo("%s Commitsyscfg:%d Setting mesh enable in syscfg to %d\n",
        __FUNCTION__,commitSyscfg,enable);
    // Always commit to syscfg DB in XB3 to keep the syscfg DB of Arm and Atom in sync
    if((commitSyscfg || isXB3Platform) &&
        (Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, (enable?"true":"false"), true) != 0)) {
         MeshInfo("Failed to set the Mesh Enable in syscfg, retrying 5 times\n");
         for(i=0; i<5; i++) {
         if(!Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, (enable?"true":"false"), true)) {
           MeshInfo("syscfg set passed in %d attempt\n", i+1);
           break;
         }
         else{
          MeshInfo("syscfg set retrial failed in %d attempt\n", i+1);
          t2_event_d("SYS_ERROR_SyscfgSet_retry_failed",  1);
         }
      }
   }
   else
    MeshInfo("mesh enable set in the syscfg successfully\n");

  if(enable) {
    MeshInfo("Set the flag in persistent memory for syscfg error recovery\n");
    fpMeshFile = fopen(MESH_ENABLED ,"a");
    if (fpMeshFile)
        fclose(fpMeshFile);
    else
        MeshInfo("fpMeshFile is NULL\n");
  } else
  {
   if(!remove(MESH_ENABLED))
    MeshInfo("Mesh Flag removed from persistent memory\n");
   else
    MeshError("Failed to remove Mesh Flag from persistent memory\n");
  }
}

void Mesh_EBCleanup()
{
    int rc = -1;

    rc = v_secure_system(ETHBHAUL_SWITCH " -eb_disable &" );
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("%s -eb_disable : Ethernet backhaul disable failed = %d\n", ETHBHAUL_SWITCH, WEXITSTATUS(rc));
    }

    if( (!isSkyHUB4 ) && (gmssClamped) ) {
        MeshInfo("TCP MSS clamp for XHS is disabled\n");
        sysevent_set(sysevent_fd, sysevent_token, "eb_gre", "down", 0);
        sysevent_set(sysevent_fd, sysevent_token, "firewall-restart", NULL, 0);
        gmssClamped = false;
    }
}

static void Mesh_sendCaCert(bool value)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    // Set sync message type
    mMsg.msgType = MESH_CA_CERT;
    mMsg.data.comodoCa.is_comodo_enabled = value;
    msgQSend(&mMsg);
}

/**
 * @brief Mesh Agent Comodo ca cert Enable/Disable
 *
 * This function will enable Comodo Ca or plume ca for establishing controller/nlb/mqtt Connection
 */
bool Mesh_SetMeshCaCert(bool enable, bool init, bool commitSyscfg)
{
    bool ret = false;

 // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_CA_CERT].sysStr) != enable)
    {
        MeshInfo("%s: Comodo Ca Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            ret = meshSetSyscfgBool(enable,MESH_CA_CERT);
        }

        if (ret == true || commitSyscfg == false)
            g_pMeshAgent->IsComodoCaCertEnabled = enable;

        //Send this as an syc msg to plume manager
        Mesh_sendCaCert(enable);
    }
    return TRUE;
}

/**
 * @brief Mesh Agent dscp inherit kernel module Enable/Disable
 *
 * This function will enable dscp kernel module to inherit gre encapsulated packet
 * with inner ip header dscp flag value to outer ip header dscp value.
 */
bool Mesh_SetMeshDscpInheritKernelModule(bool enable, bool init, bool commitSyscfg)
{
    bool ret = false;

 // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_DSCP_INHERIT_ENABLE].sysStr) != enable)
    {
        MeshInfo("%s: dscp inherit kernel module Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            ret = meshSetSyscfgBool(enable,MESH_DSCP_INHERIT_ENABLE);
        }

        if (ret == true || commitSyscfg == false)
            g_pMeshAgent->dscpInheritRfcEnable = enable;

         Mesh_handleDscpInheritKernelModule(enable);
    }
    return TRUE;
}

/**
 * @brief Mesh Agent handle dscp inherit kernel module
 *
 * This function will insert and remove dscp kernel module based
 * on the rfc.
 */
bool Mesh_handleDscpInheritKernelModule(bool enable)
{
    int rc = -1;

    if (enable)
    {
        if (g_pMeshAgent->IsdscpConfigEnabled && g_pMeshAgent->IsPodConnect)
        {
            rc= v_secure_system("systemctl start greinheritance.service");
            if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
                MeshError("systemctl start greinheritance.service rc = %d\n",WEXITSTATUS(rc));
            MeshInfo("%s:xmeshgre.ko is inserted sucessfully\n",__FUNCTION__);
        }
    }
    else
    {
        if (g_pMeshAgent->IsdscpConfigEnabled && g_pMeshAgent->IsPodConnect)
        {
            rc= v_secure_system("systemctl stop greinheritance.service");
            if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
                MeshError("rmmod xmeshgre.ko failed :  rc = %d\n", WEXITSTATUS(rc));
        }
    }
    return TRUE;
}

/**
 * @brief Send recorder Enable/Disable
 *
 * This function will send the recorder rfc
 * via rbus to TS
 */

bool Mesh_sendRecorderConfig()
{
    bool success = TRUE;
    int recorder_enable = 0;

    MeshInfo("Entering into %s\n",__FUNCTION__);
    recorder_enable  = g_pMeshAgent->recorderEnable ?  1 : 0;
    publishRBUSEvent(RECORDER_ENABLE_EVENT, (void *)&recorder_enable,handle);

    return success;
}


/**
 * @brief Recorder Enable/Disable
 *
 * This function will enable/disable recorder
 */

bool Recorder_SetEnable(bool enable, bool init, bool commitSyscfg)
{
    bool ret = false;

 // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_RECORDER_ENABLE].sysStr) != enable)
    {
        MeshInfo("%s:recorder enable Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            ret = meshSetSyscfgBool(enable,MESH_RECORDER_ENABLE);
        }

        if (ret == true || commitSyscfg == false)
            g_pMeshAgent->recorderEnable = enable;

         Mesh_sendRecorderConfig();
    }
    return TRUE;
}

bool Recorder_UploadEnable(bool enable, bool init, bool commitSyscfg)
{
    bool ret = false;
    if (init || Mesh_GetEnabled("hcm_recording_upload_enable") != enable)
    {
        MeshInfo("%s:recorder upload enable Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            ret = meshSet_HCMUploadEnable_syscfg(enable);
        }
        g_pMeshAgent->hcm_recording_upload_enable = enable;
    }
    return ret;
}

/**
 * @brief Mesh Agent EthBhaul Set Enable/Disable
 *
 * This function will enable/disable the Mesh Pod ethernet backhaul feature enable/disable
 */
bool Mesh_SetMeshEthBhaul(bool enable, bool init, bool commitSyscfg)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr) != enable)
    {
        MeshInfo("%s: Ethbhaul Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            meshSetEthbhaulSyscfg(enable);
        }
        g_pMeshAgent->PodEthernetBackhaulEnable = enable;
        //Send this as an RFC update to plume manager
        Mesh_sendRFCUpdate("PodEthernetGreBackhaul.Enable", enable ? "true" : "false", rfc_boolean);
    // If ethernet bhaul is disabled, send msg to dnsmasq informing same with a dummy mac    
        if(!enable)
        {
          Mesh_EBCleanup();
          Mesh_SendEthernetMac("00:00:00:00:00:00");
        }
    }
    return TRUE;
}
#ifdef ONEWIFI
/**
 * @brief Mesh Agent SetXleModeCloudCtrlEnable Set Enable/Disable
 *
 * This function will enable/disable the Mesh XleModeCloudCtrlEnable RFC enable/disable
 */
bool Mesh_SetXleModeCloudCtrlEnable(bool enable, bool init, bool commitSyscfg)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_XLE_MODE_CLOUD_CTRL_RFC].sysStr) != enable)
    {
        MeshInfo("%s: XleModeCloudCtrlEnable Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            meshSetXleModeCloudCtrlEnableSyscfg(enable);
        }
        g_pMeshAgent->XleModeCloudCtrlEnable = enable;
        //Send this as an RFC update to plume manager
        Mesh_sendRFCUpdate("XleModeCloudCtrlEnable.Enable", enable ? "true" : "false", rfc_boolean);
    }
    return TRUE;
}
#endif
#ifdef WAN_FAILOVER_SUPPORTED

static void Mesh_CreatePodVlan(MeshTunnelSetVlan *conf)
{
    int rc = -1;
    /*CID 337467  Copy-paste error (COPY_PASTE_ERROR) copy_paste_error bridge in conf->bridge looks like a copy-paste error.*/
    rc = v_secure_system("ovs-vsctl add-br %s; /sbin/ifconfig %s up",conf->bridge,conf->bridge);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to add bridge %s\n", conf->bridge);
    }
    rc = v_secure_system("/sbin/vconfig add %s %d;/sbin/ifconfig %s up",conf->parent_ifname,conf->vlan,conf->ifname );
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to add VLAN %d to %s\n", conf->vlan, conf->parent_ifname);
    }

    rc = v_secure_system("ovs-vsctl add-port %s %s",conf->bridge,conf->ifname);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Failed to add %s in %s \n",conf->ifname,conf->bridge);
    }
}

static void Mesh_ext_create_lanVlans( char *ifname)
{
   char vlan_ifname[MAX_IFNAME_LEN] = {0};
   MeshTunnelSetVlan data;
   errno_t rc = -1;

   int i=0;
   int lan_vlans[] = {PRIV_VLAN,XHS_VLAN,LNF_VLAN};
   char *lan_bridges[] = {PRIV_BR,XHS_BR,LNF_BR};

   for( i = 0; i < MAX_VLANS; i++)
   {
       if((!strcmp( ifname,ETHBACKHAUL0_VLAN) || !strcmp(ifname, ETHBACKHAUL1_VLAN)) && lan_vlans[i] == PRIV_VLAN)
           continue;

       //Send the bridge config to OvsAgent
       memset(&data, 0, sizeof(MeshTunnelSetVlan));
       memset(vlan_ifname, '\0', MAX_IFNAME_LEN);

       snprintf(vlan_ifname, sizeof(vlan_ifname),
                     "%s.%d", ifname, lan_vlans[i]);
       strncpy(data.ifname,  vlan_ifname,sizeof(data.ifname));
       rc = strcpy_s(data.parent_ifname, sizeof(data.parent_ifname), ifname);
       ERR_CHK(rc);
       rc = strcpy_s(data.bridge, sizeof(data.bridge), lan_bridges[i]);
       ERR_CHK(rc);
       data.vlan = lan_vlans[i];
       MeshInfo("Mesh_ext_create_lanVlans lan vlan: %s, bridge: %s\n", data.ifname, data.bridge);
       Mesh_ModifyPodTunnelVlan(&data, false);
   }
}

/**
 * @brief Mesh Agent ExtenderBridge creation
 *
 * This function will create extender bridge which ifname as argument
 */
bool Mesh_ExtenderBridge(char *ifname)
{
    bool status = true;
    MeshTunnelSetVlan data;
    bool ret = false;
    bool bIsethpod = true;
    char vlan_ifname[MAX_IFNAME_LEN] = {0};
    int rc = -1;
    errno_t rv = -1;

    memset(&data, 0, sizeof(MeshTunnelSetVlan));

    //rbus call for bridge name from dmsb.Mesh.WAN.Interface.Name
    ret = get_wan_bridge();

    rc = v_secure_system("ovs-vsctl set bridge %s stp_enable=true",meshWANIfname);
    if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        MeshWarning("Unable to set stp to WAN backup bridge\n");

    if (strncmp(ETH_EBHAUL,ifname,(sizeof(ETH_EBHAUL)- 1)) != 0)
        bIsethpod=false;

    if (ret && !bIsethpod)
    {
    //Send the bridge config to OvsAgent
        if( strstr(ifname, MESH_ETHPORT) )
        {
            char ifname_name[MAX_IFNAME_LEN] = {0};
            char * ethportname = NULL;
            char *context = NULL;

            rv = strcpy_s(ifname_name, MAX_IFNAME_LEN, ifname);
            ERR_CHK(rv);
            strtok_r(ifname_name, "-", &context);
            ethportname = strtok_r(NULL, ".", &context);
            MeshInfo("Ethernet port is %s \n",ethportname);
            snprintf(vlan_ifname, sizeof(vlan_ifname),
                     "%s.%d", ethportname, MESH_EXTENDER_VLAN);
            rv = strcpy_s(data.parent_ifname, sizeof(data.parent_ifname), ethportname);
            ERR_CHK(rv);
        }
        else
        {
           snprintf(vlan_ifname, sizeof(vlan_ifname),
                     "%s.%d", ifname, MESH_EXTENDER_VLAN);
           rv = strcpy_s(data.parent_ifname, sizeof(data.parent_ifname), ifname);
           ERR_CHK(rv);
        }
        rv = strcpy_s(data.bridge,sizeof(data.bridge), meshWANIfname);
        ERR_CHK(rv);
        rv = strcpy_s(data.ifname, sizeof(data.ifname), vlan_ifname );
        ERR_CHK(rv);
        data.vlan = MESH_EXTENDER_VLAN;
        Mesh_ModifyPodTunnelVlan(&data,false);
    } else {
        if(!ret) {
	    status = false;
            MeshError("get_wan_bridge get failed \n");
        }
    }

    if(!strcmp( ifname, ETHBACKHAUL0_VLAN) || !strcmp( ifname, ETHBACKHAUL1_VLAN))
    {
       rc = v_secure_system("ethtool -K %s sg off",ifname);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("Failed to run ethtool -K %s sg off \n",ifname);
        }

#if defined(ONEWIFI)
      Mesh_vlan_network(ifname);
#endif
    }
    if (!bIsethpod)
        Mesh_ext_create_lanVlans(ifname);

    return status;
}
#endif
#if defined(WAN_FAILOVER_SUPPORTED)
#define GRE_POST_HOOK   "/usr/sbin/gre-post-hook.sh"
void monitor_wfo_state(bool bStatus)
{
    if(bStatus)
    {
#ifdef WAN_FAILOVER_SUPPORTED
        wfo_mode = true;
#endif
        MeshInfo("Start the Black box log\n");
        // Run diagnostics every 90 seconds, dumps disabled, wfo enabled, delay diagnostics start by 45 seconds to
        // give enough time for WFO to be initialized
        xmesh_diag_start(100, false, true, 45);
    }
    else
    {
#ifdef WAN_FAILOVER_SUPPORTED
        wfo_mode = false;
#endif
        MeshInfo("End Black box log\n");
        xmesh_diag_stop();
    }
    return;
}
void Send_MESH_WFO_ENABLED_Msg(bool bStatus)
{
    MeshSync mMsg = {0};
    static bool previousStatus = 0;
    if(previousStatus == bStatus)
    {
        MeshInfo("skip WFO status update\n");
        return;
    }
    mMsg.msgType = MESH_WFO_ENABLED;
    mMsg.data.meshWFOEnabled.isWFOEnabledSet = true;
    previousStatus = (mMsg.data.meshWFOEnabled.WFOEnabledStatus = bStatus);
    msgQSend(&mMsg);
    monitor_wfo_state(bStatus);
    return;
}
#endif

#ifndef DBUS_SUPPORT
/**
 * @brief Mesh rbusGetStringHandler
 *
 * Publish event after event value gets updated
 */
rbusError_t rbusGetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    char* payload = NULL;
    (void)handle;
    (void)opts;
#ifdef WAN_FAILOVER_SUPPORTED
    bool rc = true;
#endif

    MeshInfo("Called rbusGetStringHandler for [%s]\n",name);

    rbusValue_t value;
    rbusValue_Init(&value);
#ifdef WAN_FAILOVER_SUPPORTED
    if (strcmp(name, EVENT_MESH_WAN_IFNAME) == 0 )
    {
        if (meshWANIfname == NULL)
        rc = get_wan_bridge();

        if (rc)
            rbusValue_SetString(value, meshWANIfname);
    }
    else if (strcmp(name, EVENT_MESH_BACKHAUL_IFNAME) == 0 )
    {
        rbusValue_SetString(value, mesh_backhaul_ifname);
    }
    else
#endif
    if(strcmp(name, EVENT_MWO_TOS_CONFIGURATION) == 0 )
    {
        payload = steering_profile_event_data_get();
        if(payload)
            rbusValue_SetString(value, payload);
    }
    else if(strcmp(name, EVENT_MWO_CLIENT_TO_PROFILE_MAP_EVENT) == 0 )
    {
        payload = client_profile_event_data_get();
        if(payload)
            rbusValue_SetString(value,payload);
    }
    else if (strcmp(name,EVENT_CHANNEL_KEEPOUT) == 0)
    {
        channel_plan_doc_t  *channel_plan_data;
        channel_plan_data = g_pMeshAgent->channel_plan_data;
        if (channel_plan_data != NULL) {
            payload = channel_keepout_event_data_get(channel_plan_data);
            if (payload) {
                rbusValue_SetString(value,payload);
            }
	}
        else {
            payload = strdup("{}");
            rbusValue_SetString(value,payload);
        }
    }
    else if (strcmp(name,EVENT_HD_RECOMMENDATION) == 0)
    {
        channel_plan_doc_t *channel_plan;
        channel_plan = g_pMeshAgent->channel_plan_data;
        if (channel_plan != NULL) {
            payload = hd_recommendation_event_data_get(channel_plan);
            if (payload) {
               rbusValue_SetString(value,payload);
            }
            else if (channel_plan->HD_recc->is_blob_expired) {
                MeshInfo("HD recommendation blob expired, sending empty payload\n");
                payload = strdup("{}");
                free_hd_recc_global();
                save_hdrecc_tofile(payload);
                rbusValue_SetString(value,payload);
            }
        }
        else {
            payload = strdup("{}");
            rbusValue_SetString(value,payload);
        }
    }
    else
    {
        MeshError("Parameter not supported [%s]\n",name);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }

    if (payload)
        free(payload);

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t rbusGetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    (void)handle;
    (void)opts;

    rbusValue_t value;
    rbusValue_Init(&value);
#ifdef WAN_FAILOVER_SUPPORTED
    if (strcmp(name, EVENT_MESH_WAN_LINK) == 0 )
    {
        rbusValue_SetBoolean(value, meshWANStatus);
    }
    else if (strcmp(name, EVENT_MESH_ETHERNETBHAUL_UPLINK) == 0 )
    {
        rbusValue_SetBoolean(value, meshETHBhaulUplink);
    }
    else
#endif
    {
        MeshError("Parameter not supported [%s]\n", name);
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t rbusEventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    (void)handle;
    (void)filter;
    (void)interval;
    (void)autoPublish;

    int i;
    MeshInfo(
        "eventSubHandler called:\n" \
        "\taction=%s\n" \
        "\teventName=%s\n",
        action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
        eventName);

    for (i = 0; i<MESH_RBUS_PUBLISH_EVENT_TOTAL ; i++)
    {
        if(!strcmp(meshRbusPublishEvent[i].name, eventName))
        {
            if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
                meshRbusPublishEvent[i].subflag++;
            else
                meshRbusPublishEvent[i].subflag--;

            break;
        }
    }

    return RBUS_ERROR_SUCCESS;
}
#endif

#if defined(ONEWIFI) || defined(WAN_FAILOVER_SUPPORTED) || defined(GATEWAY_FAILOVER_SUPPORTED) || defined(RDKB_EXTENDER_ENABLED)
void changeStaState(bool state)
{
    sta.state = state;
    MeshInfo("changeStaState: sta_ifname:%s, state : %d, bssid:%s\n",sta.sta_ifname,sta.state,sta.bssid);
}

#endif

#ifndef DBUS_SUPPORT
/**
 * @brief Mesh meshRbusInit
 *
 * Initialize Rbus and data elements
 */
rbusError_t meshRbusInit()
{
    int rc = RBUS_ERROR_SUCCESS;
#if defined(WAN_FAILOVER_SUPPORTED)
    if(!get_wan_bridge())
        MeshError("get_wan_bridge failed\n");
#endif
    rc = rbus_open(&handle, CCSP_COMPONENT_ID);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        MeshError("Mesh rbus initialization failed\n");
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }
    // Register data elements
    rc = rbus_regDataElements(handle, NUM_OF_RBUS_PARAMS, meshRbusDataElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        MeshError(("Mesh rbus register data elements failed\n"));
        rc = rbus_close(handle);
        return rc;
    }
    return rc;
}

int getSpeedTestTimeout()
{
    char const* name = RBUS_SPEEDTEST_TIMEOUT;
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    int speedtest_timeout;
    rc = rbus_get(handle, name, &value);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        MeshError("%s: %d rbus_get failed for %s with error %d\n", __func__, __LINE__,  name, rc);
        return -1;
    }
    speedtest_timeout = rbusValue_GetUInt32(value);
    MeshInfo("%s: Speedtest timeout: %d\n", __func__, speedtest_timeout);
    rbusValue_Release(value);
    return speedtest_timeout;
}
void Mesh_sendSpeedtestMsg(int status, int speedtest_timeout)
{
    MeshSync mMsg = {0};

    // Set sync message type
    mMsg.msgType = MESH_SYNC_SM_PAUSE;
    mMsg.data.speedtestCfg.status = status;
    mMsg.data.speedtestCfg.timeout = speedtest_timeout;
    if(status == ST_TR181_STATUS_STARTING || status == ST_TR181_STATUS_COMPLETE)
    {
        MeshInfo("MESH_SYNC_SM_PAUSE msgQsend Status:%d Timeout:%d\n",
                        mMsg.data.speedtestCfg.status, mMsg.data.speedtestCfg.timeout);
        msgQSend(&mMsg);
    }
}

void speedTestHandler(rbusHandle_t handle, rbusEvent_t const* event,
                                           rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;
    int speedtest_status;
    int speedtest_timeout;

    rbusValue_t value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        MeshError("%s:%d FAIL: value is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    speedtest_status = rbusValue_GetUInt32(value);
    MeshInfo("Received SpeedTest Status event %d\n", speedtest_status);

    speedtest_timeout = getSpeedTestTimeout();
    if (speedtest_timeout >= 0)
    {
        Mesh_sendSpeedtestMsg(speedtest_status, speedtest_timeout);
    }
}

bool subscribeSpeedTestStatus()
{
    bool ret = true;

    MeshInfo("Rbus events subscription start %s\n", RBUS_SPEEDTEST_STATUS);
    ret = rbusEvent_Subscribe(handle, RBUS_SPEEDTEST_STATUS, speedTestHandler, NULL, 0);
    if (ret != RBUS_ERROR_SUCCESS) {
        MeshError("Rbus events subscribe failed:%s\n", RBUS_SPEEDTEST_STATUS);
        ret = false;
    }
   return ret;
}
#endif
int mesh_waitRestart()
{
    int err = -1;
#ifdef RDKB_EXTENDER_ENABLED
    int fd,wd;
    struct timeval tv;
    fd_set fds;

    tv.tv_sec = 120;
    tv.tv_usec = 0;

    fd = inotify_init();
    if (fd == -1) {
        MeshInfo("Restart Mesh failed during inotify_init\n");
	return err;
    }
    wd = inotify_add_watch(fd, "/tmp/mesh_agent_stop_check", IN_DELETE_SELF);
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    if((wd == -1) || (select(fd + 1, &fds, NULL, NULL, &tv)!= -1) ) {
	//wd = -1 is file not present so restart mesh instantly
	//or wait for 120 or wait till the file is deleted
#endif
        MeshInfo("Restart Mesh start\n");
        if ((err = svcagt_set_service_restart (meshServiceName)) != 0)
        {
            MeshInfo("Restart Mesh failed\n");
        }
#ifdef RDKB_EXTENDER_ENABLED
	if(!access("/tmp/mesh_handler_stop_check", F_OK )) {
            if(remove("/tmp/mesh_handler_stop_check") == 0) {
                MeshInfo("File /tmp/mesh_handler_stop_check deleted successfully.\n");
            }
            else {
                MeshInfo("Error deleting file /tmp/mesh_handler_stop_check.\n");
            }
        }
         MeshInfo("Restart Mesh end\n");
    }
    inotify_rm_watch(fd, wd);
    close(fd);
#endif
    return err;
}

#if defined(WAN_FAILOVER_SUPPORTED) || defined(ONEWIFI) || defined(GATEWAY_FAILOVER_SUPPORTED)
#if !defined(DBUS_SUPPORT)
int getRbusStaIfName(unsigned int index)
{
    rbusValue_t value;
    bool ret = true;
    char name[MAX_IFNAME_LEN];
    int rc = RBUS_ERROR_SUCCESS;
    const char* newValue;

    rbusValue_Init(&value);
    sprintf(name, WIFI_STA_INTERFACE_NAME,index);
    rc = rbus_get(handle, name, &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        MeshError ("rbus_get failed for [%s] with error [%d]\n", name, rc);
        ret = false;
    }

    newValue = rbusValue_GetString(value, NULL);
    snprintf(sta.sta_ifname, MAX_IFNAME_LEN, "%s", newValue);
    MeshInfo("Sta if_name = [%s]\n", sta.sta_ifname);
    rbusValue_Release(value);

    return ret;
}
#endif

#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
void *uplinkHandleFunction()
{
    char local_ip[MAX_IP_LEN];
    char remote_ip[MAX_IP_LEN];

    is_uplink_tid_exist = 1;
    udhcpc_stop(GATEWAY_FAILOVER_BRIDGE);
    handle_uplink_bridge(NULL, NULL, NULL, false);
    //Stop the mesh and create a temporary uplink GRE
    MeshInfo("Stopping meshwifi service\n");
    // If the service is running, stop it
    if ((svcagt_get_service_state(meshServiceName) || g_pMeshAgent->meshEnable))
    {
        if(svcagt_set_service_state(meshServiceName, false))
        {
            MeshWarning("%s Failed to stop\n",meshServiceName);
        }
    }
    else
    {
        MeshWarning("%s Is not running\n",meshServiceName);
    }
    //Start udhcpc for connected interface
    if(!udhcpc_start(sta.sta_ifname))
    {
        MeshWarning("Failed to start udhcpc for %s\n",sta.sta_ifname);
    }

    if (get_ipaddr_subnet(sta.sta_ifname, local_ip, remote_ip))
    {
        if(!handle_uplink_bridge(sta.sta_ifname, local_ip, remote_ip, true))
        {
            if(udhcpc_start(GATEWAY_FAILOVER_BRIDGE))
	    {
                if (get_ipaddr_subnet(GATEWAY_FAILOVER_BRIDGE, local_ip, remote_ip))
                {
#if !(defined DBUS_SUPPORT)
                    publishRBUSEvent(MESH_RBUS_PUBLISH_BACKHAUL_IFNAME, (void *)GATEWAY_FAILOVER_BRIDGE,handle);
#endif
		    snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", GATEWAY_FAILOVER_BRIDGE);
		}
            }
	}
    }
    else
    {
        MeshWarning("Ip is not configured for %s, So uplink GRE is not created\n",sta.sta_ifname);
    }
    udhcpc_stop(sta.sta_ifname);
    is_uplink_tid_exist = 0;

    return NULL;
}
#endif

#if !(defined DBUS_SUPPORT)
int getRbusStaBssId(unsigned int index)
{
    rbusValue_t value;
    char name[MAX_IFNAME_LEN];
    int rc = RBUS_ERROR_SUCCESS;
    bool ret = true;
    const char* newValue;

    rbusValue_Init(&value);
    sprintf(name, WIFI_STA_BSSID,index);
    rc = rbus_get(handle, name, &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        MeshError ("rbus_get failed for [%s] with error [%d]\n", name, rc);
        ret = false;
    }
    newValue = rbusValue_GetString(value, NULL);
    snprintf(sta.bssid, MAX_BSS_ID_STR, "%02x:%02x:%02x:%02x:%02x:%02x", *newValue, \
             *(newValue +1),*(newValue +2),*(newValue +3),*(newValue +4), \
             *(newValue +5));
    MeshInfo("Sta bssid: [%s]\n", sta.bssid);
    rbusValue_Release(value);

    return ret;
}

void rbusSubscribeHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;
#if defined(ONEWIFI)
    int len;
    bool conn_status;
    unsigned int index = 0;
    unsigned int sta_connect_status = 0;
    wifi_sta_conn_info_t connect_info;
    const unsigned char *temp_buff;
#endif 
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
    int err;
    bool is_gateway_present = false;
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    int new_device_mode;
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    bool is_connect_timeout;
#endif

    if (event->name == NULL)
    {
        MeshError("%s:%d Event name is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    rbusValue_t value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        MeshError("%s:%d FAIL: value is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    MeshInfo("%s:%d Rbus event name=%s\n",__FUNCTION__, __LINE__, event->name);
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)

    if (strcmp(event->name,RBUS_DEVICE_MODE) == 0)
    {
        //Handle device mode
        new_device_mode = rbusValue_GetUInt32(value);
        MeshInfo("New Device Mode = %d, Old Device Mode = %d\n",new_device_mode,device_mode);
	if (new_device_mode == GATEWAY_MODE)
        {
            if(ping_ip(MESH_BHAUL_INETADDR))
                MeshInfo("Gateway Ip is reachable, still changing the device mode to gateway\n");
            snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", MESH_BHAUL_BRIDGE);
            publishRBUSEvent(MESH_RBUS_PUBLISH_BACKHAUL_IFNAME, (void *)mesh_backhaul_ifname,handle);
        }
	else
            snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", MESH_XLE_BRIDGE);

        if(new_device_mode != device_mode)
        {
            handle_led_status(MESH_CONTROLLER_CONNECTING, new_device_mode);
            meshETHBhaulUplink = false;
            MeshInfo("meshETHBhaulUplink: false when device_mode switch\n");
            publishRBUSEvent(MESH_RBUS_PUBLISH_ETHBACKHAUL_UPLINK, (void *)&meshETHBhaulUplink,handle);
            device_mode = new_device_mode;
            MeshInfo("Device Mode changed, Sending the notification to managers\n");
            Mesh_sendCurrentSta();
        }
    }
     else
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    if(strcmp(event->name,RBUS_STA_CONNECT_TIMEOUT) == 0)
    {
        MeshInfo("Received RBUS_STA_CONNECT_TIMEOUT event\n");
        is_connect_timeout = rbusValue_GetBoolean(value);

        if (!is_connect_timeout)
        {
            MeshError("Wrong %s value %d",RBUS_STA_CONNECT_TIMEOUT, is_connect_timeout);
            return;
        }
        Mesh_sendEbhStatusRequest();
    }
    else
#endif //WAN_FAILOVER_SUPPORTED || RDKB_EXTENDER_ENABLED
#if defined(WAN_FAILOVER_SUPPORTED)
    if(strcmp(event->name,RBUS_WAN_CURRENT_ACTIVE_INTERFACE) == 0) //Gateway side alone
    {
        const char *CurrentActiveInterface = rbusValue_GetString(value, NULL);
        static bool previous_wfo_enabled = 0;
        bool wfo_enabled;
        int rc;
        MeshInfo("Received RBUS_WAN_CURRENT_ACTIVE_INTERFACE Inter:%s\n",CurrentActiveInterface);
        wfo_enabled = (strncmp(CurrentActiveInterface, REMOTE_INTERFACE_NAME,
                sizeof(REMOTE_INTERFACE_NAME)) == 0);
        if (previous_wfo_enabled != wfo_enabled)
        {
            monitor_wfo_state(wfo_enabled);
            MeshInfo("Info %s WFO %d\n",GRE_POST_HOOK, wfo_enabled);
            rc= v_secure_system("%s WFO %d", GRE_POST_HOOK, wfo_enabled);
            if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
            {
                MeshError("Error %s WFO %d\n",GRE_POST_HOOK, wfo_enabled);
            }
            previous_wfo_enabled = wfo_enabled;
        }
    }
    else
#endif //WAN_FAILOVER_SUPPORTED
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
    if (strcmp(event->name,RBUS_GATEWAY_PRESENT) == 0)
    {
        //Handle External Gateway Present
        is_gateway_present = rbusValue_GetBoolean(value);
        gateway_present = is_gateway_present?1:0;
        MeshInfo("ExternalGatewayPresent  = %d\n",gateway_present);
        if(gateway_present == AP_ACTIVE)
	{
            handle_uplink_bridge(NULL, NULL, NULL, false);
            udhcpc_stop(sta.sta_ifname);
            udhcpc_stop(GATEWAY_FAILOVER_BRIDGE);
	    publishRBUSEvent(MESH_RBUS_PUBLISH_BACKHAUL_IFNAME, (void *)MESH_BHAUL_BRIDGE, handle);
	    snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", MESH_BHAUL_BRIDGE);

	    if (g_pMeshAgent->meshEnable)
            {
                if ((err = svcagt_set_service_state(meshServiceName, true)) != 0)
                    MeshWarning("Start Mesh failed");
	    }
	    else
	        MeshWarning("Mesh is disabled");
	}
    }
    else
#endif
#if defined(ONEWIFI) 
    if (strstr(event->name,"Connection.Status"))
    {
        //Handle sta connection status
	sscanf(event->name, RBUS_STA_STATUS_INDEX, &index);
        temp_buff = rbusValue_GetBytes(value, &len);
        if (temp_buff == NULL) {
            MeshError("%s:%d Rbus get string failure len=%d\n", __FUNCTION__, __LINE__, len);
            return;
        }

        memcpy(&connect_info, temp_buff, len);
        conn_status = (connect_info.connect_status == wifi_connection_status_connected) ? true:false;
        snprintf(sta.bssid, MAX_BSS_ID_STR, "%02x:%02x:%02x:%02x:%02x:%02x", connect_info.bssid[0], \
             connect_info.bssid[1],connect_info.bssid[2],connect_info.bssid[3],connect_info.bssid[4], \
             connect_info.bssid[5]);
        getRbusStaIfName(index);
	//Station mode & uplink GRE support in the main gateway
        sta_connect_status = conn_status?1:0;
        MeshInfo("%s:Ifname:%s Bssid:%s connect_status = %d \n",__FUNCTION__,sta.sta_ifname, sta.bssid,sta_connect_status);

#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
	if ((gateway_present == STA_ACTIVE))
        {
            if(sta_connect_status)
            {
                MeshInfo("Starting thread to create brSTA uplink, ExternalGatewayPresent = %d\n",gateway_present);
	        pthread_create(&tid_handle, NULL, uplinkHandleFunction,NULL);
            }
	    else
	    {
		if(is_uplink_tid_exist)
		{
		    MeshInfo("Stop the thread, still running, clear all bridges\n");
		    if (pthread_kill( tid_handle, SIGUSR1) < 0)
                        MeshInfo("pthread_kill failed");

                    handle_uplink_bridge(NULL, NULL, NULL, false);
		    is_uplink_tid_exist = 0;
		}
	    }
        }
        else
	{
#endif

            if (conn_status == true)
            {
                MeshInfo("%s:Station Connected to ifname:%s Bssid:%s\n",__FUNCTION__,sta.sta_ifname, sta.bssid);
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
                if(device_mode == EXTENDER_MODE)
                    handle_led_status(MESH_STA_CONNECTED, device_mode);
#endif
                changeStaState(true);
                Mesh_sendStaInterface(sta.sta_ifname,sta.bssid,true);
            }
            else
            {
                MeshInfo("%s:Station Disconnected from  ifname:%s Bssid:%s\n",__FUNCTION__,sta.sta_ifname, sta.bssid);
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
                if (!is_eth_connected())
                {
                    if(device_mode == EXTENDER_MODE)
                        handle_led_status(MESH_STA_DISCONNECTED, device_mode);
                }
#endif
                if (sta.state)
                {
                    changeStaState(false);
                    Mesh_sendStaInterface(sta.sta_ifname,sta.bssid, false);
                }
            }
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
        }
#endif
    }
#endif
#if defined(ONEWIFI) 
    else
#endif
        MeshError("Undefined event name\n");
}

void  *handle_rbus_Subscribe()
{
    int i = (MESH_RBUS_EVENT_TOTAL-1);
    bool ret = false;
    int count = 0;

    while (count != (MESH_RBUS_EVENT_TOTAL))
    {
	if(!meshRbusEvent[i].status)
        {
            ret = rbusEvent_Subscribe(handle, meshRbusEvent[i].name, rbusSubscribeHandler, NULL, 0);
#if defined(_RDKB_GLOBAL_PRODUCT_REQ_)
	    if ( (ret != RBUS_ERROR_SUCCESS) && (meshRbusEvent[i].feature_supported) )
#else
        if (ret != RBUS_ERROR_SUCCESS)
#endif /** _RDKB_GLOBAL_PRODUCT_REQ_ */
            {
                MeshError("Rbus events subscribe failed:%s\n",meshRbusEvent[i].name);
		sleep(2);
	    }
            else
            {
		MeshInfo("Rbus events subscribe sucess:%s count = %d\n",meshRbusEvent[i].name,count);
                count++;
                meshRbusEvent[i].status = true;
            }
	}
	i = (--i < 0)?(MESH_RBUS_EVENT_TOTAL-1):i;
    }
    MeshInfo("handle_rbus_Subscribe thread exited");
    return NULL;
}
#endif
#endif

#if !defined DBUS_SUPPORT && !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
void rbus_get_gw_present()  
{
    rbusValue_t value;
    unsigned int data;
    int rc = RBUS_ERROR_SUCCESS;

    rc = rbus_get(handle,RBUS_GATEWAY_PRESENT, &value);

    if(rc != RBUS_ERROR_SUCCESS) {
        MeshInfo("gateway present rbus get failed");
	publishRBUSEvent(MESH_RBUS_PUBLISH_BACKHAUL_IFNAME, (void *)MESH_BHAUL_BRIDGE, handle);
	snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", MESH_BHAUL_BRIDGE);
        return;
    }

    data = rbusValue_GetBoolean(value);
    gateway_present = data?1:0;
    rbusValue_Release(value);

    MeshInfo("rbus_get for %s: value:%s\n",RBUS_GATEWAY_PRESENT, (data?"STA_ACTIVE":"AP_ACTIVE"));
    if(gateway_present == STA_ACTIVE)
    {
        if (sta.state)
        {
            MeshInfo(("STA is associated and gateway_present == STA_ACTIVE, create brSTA\n"));
	    pthread_create(&tid_handle, NULL, uplinkHandleFunction,NULL);
        }
    }
    else
    {
        publishRBUSEvent(MESH_RBUS_PUBLISH_BACKHAUL_IFNAME, (void *)MESH_BHAUL_BRIDGE, handle);
        snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", MESH_BHAUL_BRIDGE);
    }
}
#endif
#if defined(WAN_FAILOVER_SUPPORTED)
void Mesh_backup_network(char *ifname, eMeshDeviceMode type, bool status)
{
    char cmd[256]={0};
    static bool previous = false, is_eth_up = false;

    MeshInfo("Received MESH_BACKUP_NETWORK for %s interface : %s \n",type ? "Gateway" : "Extender",ifname);
    is_eth_up = (strstr(ifname,MESH_ETHPORT) != NULL);

    //Delete ppd-<>.200 from brRWAN if pgd got deleted from Wifi_Inet_Config
    if(!is_eth_up && !status && type)
    {
        v_secure_system("/usr/bin/ovs-vsctl del-port %s %s.%d",REMOTE_INTERFACE_NAME,ifname,MESH_EXTENDER_VLAN);
        MeshInfo("Removed /usr/bin/ovs-vsctl del-port %s %s.%d\n",REMOTE_INTERFACE_NAME,ifname,MESH_EXTENDER_VLAN);
        return;
    }

    if(!type)
    {
        if (is_eth_up && !status)
        {
            meshETHBhaulUplink = false;
            MeshInfo("Eth : got disconnected: %s\n",ifname);
#if !defined DBUS_SUPPORT
            publishRBUSEvent(MESH_RBUS_PUBLISH_ETHBACKHAUL_UPLINK, (void *)&meshETHBhaulUplink, handle);
#endif
	    return;
        }
        else
        {
            meshETHBhaulUplink = is_eth_up;
            MeshInfo("%s : got connected: %s\n",(is_eth_up?"Eth":"Wi-Fi"),ifname);
#if !defined DBUS_SUPPORT
            publishRBUSEvent(MESH_RBUS_PUBLISH_ETHBACKHAUL_UPLINK, (void *)&meshETHBhaulUplink, handle);
#endif
	}
    }

    if (Mesh_ExtenderBridge(ifname))
    {
        snprintf(cmd, sizeof(cmd), "up");
        meshWANStatus = true;
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "down");
    }
    MeshInfo("Notify MESH_BACKUP_NETWORK cmd:%s connect: %d\n",cmd,(meshWANStatus ?  1 : 0));
    Mesh_SyseventSetStr(meshSyncMsgArr[MESH_BACKUP_NETWORK].sysStr, cmd, 0, false);
    MeshInfo("Notify MESH_BACKUP_NETWORK current:%d, previous:%d\n",meshWANStatus,previous);
    if (meshWANStatus != previous)
    {
        Mesh_SyseventSetStr(meshSyncMsgArr[MESH_BACKUP_NETWORK].sysStr, cmd, 0, false);
#if !defined DBUS_SUPPORT
        int connect = 0;
        connect = meshWANStatus ?  1 : 0;
        publishRBUSEvent(MESH_RBUS_PUBLISH_WAN_LINK, (void *)&connect,handle);
#endif
    }
    previous = meshWANStatus;
}
#endif
#ifdef ONEWIFI
int Mesh_vlan_network(char *ifname)
{
    int rc = -1, i, numVLANs = 2;
    int VLANs[]={XHS_VLAN,LNF_VLAN};

    for( i=0 ; i < numVLANs; i++ )
    {
        rc = v_secure_system("/sbin/vconfig add %s %d",ifname,VLANs[i]);
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
           MeshWarning("Failed to create VLAN %s %d\n",ifname,VLANs[i]);

        rc = v_secure_system("/sbin/ifconfig %s.%d up",ifname,VLANs[i]);
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
           MeshError("Failed to bring up  VLAN %s %d interface\n",ifname,VLANs[i]);
    }
    return rc;
}

#if !defined DBUS_SUPPORT
int Mesh_rebootDevice()
{
    int rc = RBUS_ERROR_SUCCESS;

    MeshError("%s: Device Reboot triggered",__func__);
    rc = rbus_setStr(handle, "Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason", "sta-conn-failed");
    if (rc == RBUS_ERROR_SUCCESS) {
        rc = rbus_setStr(handle, "Device.X_CISCO_COM_DeviceControl.RebootDevice", "Device");
        if (rc != RBUS_ERROR_SUCCESS) {
            MeshError("%s: rbusWrite Failed error :%d",__func__,rc);
        }
    }
    else
    {
        MeshError("%s: rbusWrite Failed error :%d",__func__,rc);
    }
    return rc;
}
#endif

void  Mesh_sendCurrentSta()
{
    MeshInfo("send currrent sta: sta_ifname:%s, bssid:%s\n",(sta.state ? sta.sta_ifname: NULL),(sta.state ? sta.bssid : NULL));
    Mesh_sendStaInterface(sta.state ? sta.sta_ifname: NULL , sta.state ? sta.bssid : NULL, sta.state ? true : false);
}

#if !defined DBUS_SUPPORT
void Mesh_setXleModeChangeRbus(bool enable)
{
    int rc = -1;
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, enable);

    rc = rbus_set(handle, MESH_GATEWAY_NOT_ACTIVE, value, NULL);
    if(rc == RBUS_ERROR_SUCCESS)
    {
        MeshInfo(("Successfully Published MESH_GATEWAY_ENABLE\n"));
    }
    else
    {
        MeshInfo(("Error in publishing MESH_GATEWAY_ENABLE\n"));
    }
}

int get_sta_active_interface_name()
{
    int rc = RBUS_ERROR_SUCCESS;
    int numOfInputParams = 0, numOfOutVals = 0;
    const char *pInputParam[5] = {0, 0};
    char first_arg[64] = "Device.WiFi.STA.";
    rbusProperty_t outputVals = NULL;
    int i = 0;
    unsigned int index = 0;
    int len = 0;
    bool conn_status;
    wifi_connection_status_t connect_status;
    const unsigned char *temp_buff;
    const unsigned char *name = NULL;

    pInputParam[numOfInputParams] = first_arg;
    numOfInputParams = 1;

    rc = rbus_getExt(handle, numOfInputParams, pInputParam, &numOfOutVals, &outputVals);
    if(RBUS_ERROR_SUCCESS == rc) {
        rbusProperty_t next = outputVals;
        for (i = 0; i < numOfOutVals; i++) {
            name = NULL;
            rbusValue_t val = rbusProperty_GetValue(next);
            rbusValueType_t type = rbusValue_GetType(val);
            MeshInfo ("Parameter %2d:\n\r", i+1);
            if(type == RBUS_BYTES) {
                temp_buff = rbusValue_GetBytes(val, &len);
                name = rbusProperty_GetName(next);
                if(strstr(name,"Connection.Status") == NULL) {
                    MeshInfo ("Skip Parameter Name: %s\n", name);
                    next = rbusProperty_GetNext(next);
                    continue;
                }
                MeshInfo ("Checking Parameter Name: %s\n", name);
                sscanf(name, RBUS_STA_STATUS_INDEX, &index);
                if (temp_buff == NULL) {
                    MeshError("%s:%d Rbus get string failure len=%d\n", __FUNCTION__, __LINE__, len);
                    rbusProperty_Release(outputVals);
                    return -1;
                }
                memcpy(&connect_status, temp_buff, sizeof(wifi_connection_status_t));
                conn_status = (connect_status == wifi_connection_status_connected) ? true:false;
                if (conn_status == true) {
                    getRbusStaIfName(index);
		            getRbusStaBssId(index);

                    changeStaState(true);
                    MeshInfo("%s:Connected to sta ifname:%s, bssid:%s\n",__FUNCTION__,sta.sta_ifname,sta.bssid);
#if defined (RDKB_EXTENDER_ENABLED)

#endif
                    break;
                }
            }
            next = rbusProperty_GetNext(next);
        }
        /* Free the memory */
        rbusProperty_Release(outputVals);
    } else {
        MeshInfo ("Failed to get the data. Error : %d\n\r",rc);
        return -1;
    }

    return 0;
}
#endif
#endif
/**
 * @brief Mesh Cache Status Set Enable/Disable
 *
 * This function will enable/disable the Mesh Cache feature
 */
void Mesh_SetCacheStatus(bool enable, bool init, bool commitSyscfg)
{
    if (init || Mesh_GetEnabled("mesh_cache") != enable)
    {
        MeshInfo("%s: Enable:%d, Init:%d, Commit:%d.\n", __FUNCTION__, enable, init, commitSyscfg);
        if (commitSyscfg)
            Mesh_setCacheStatusSyscfg(enable);
        g_pMeshAgent->CacheEnable = enable;
        Mesh_sendRFCUpdate("MeshGREBackhaulCache.Enable", enable ? "true" : "false", rfc_boolean);
    }
}

/**
 * @brief Mesh Legacy Security Schema Set Enable/Disable
 *
 * This function will enable/disable the Mesh Legacy Security Schema
 */
void Mesh_SetSecuritySchemaLegacy(bool enable, bool init, bool commitSyscfg)
{
    if (init || Mesh_GetEnabled("mesh_security_legacy") != enable)
    {
        MeshInfo("%s: Enable:%d, Init:%d, Commit:%d.\n", __FUNCTION__, enable, init, commitSyscfg);
        if (commitSyscfg)
            Mesh_setSecuritySchemaLegacySyscfg(enable);
        g_pMeshAgent->SecuritySchemaLegacyEnable = enable;
        Mesh_sendRFCUpdate("MeshSecuritySchemaLegacy.Enable", enable ? "true" : "false", rfc_boolean);
    }
}

/**
 * @brief Mesh Retry Connection Optimization Enable/Disable
 *
 * This function will enable/disable the Mesh Optimized connection retry
 */
bool Mesh_SetMeshRetryOptimized(bool enable, bool init, bool commitSyscfg)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_REDUCED_RETRY].sysStr) != enable)
    {
        MeshInfo("%s: mesh_conn_opt_retry Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            meshSetMeshRetrySyscfg(enable);
        }
        g_pMeshAgent->MeshRetryOptimized = enable;
        //Send this as an RFC update to plume manager
        Mesh_sendReducedRetry(enable);
    }
    return TRUE;
}

/**
 * @brief Wifi Motion Enable/Disable
 *
 * This function will enable/disable wifi motion
 */
bool Mesh_SetMeshWifiMotion(bool enable, bool init, bool commitSyscfg)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_MOTION].sysStr) != enable)
    {
        MeshInfo("%s: mesh wifi motion Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            meshwifiMotionSyscfg(enable);
        }
        g_pMeshAgent->meshwifiMotionEnable = enable;
    }
    return TRUE;
}

bool Mesh_SetHDRecommendationEnable(bool enable, bool init, bool commitSyscfg)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled("mesh_hd_recommendation_enable") != enable)
    {
        MeshInfo("%s: mesh HDRecommendation Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if(commitSyscfg) {
            meshSet_HDRecommendation_Syscfg(enable);
        }
        g_pMeshAgent->HDRecommendation_Enable = enable;

        // If HD Recommendation is disabled, reset the HD recommendation state
        if (!enable)
        {
            char *payload = strdup("{}");
            rbusValue_t value;

            rbusValue_Init(&value);
            rbusValue_SetString(value, payload);
            publishRBUSEvent(HD_RECOMMENDATION_EVENT, (void *)payload, handle);
            save_hdrecc_tofile(payload);
            free_hd_recc_global();

            rbusValue_Release(value);
            free(payload);
        }
    }

    return TRUE;
}

void MeshWifiOptimizationHandle(eWifiOptimizationMode mode)
{
    bool mesh_is_enabled = false;
    int err = 0;

    mesh_is_enabled = Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr);

    switch (mode)
    {
        case MESH_MODE_MONITOR:
             if (!mesh_is_enabled)
             {
                 MeshInfo("HCM RFC Status: Monitor , HCM Device Status: %s , Reason: Mesh is disabled\n",(g_pMeshAgent->meshWifiOptimizationMode==MESH_MODE_ENABLE?"Enable":"Disable"));
                 isReserveModeActive = true;
                 if ((err = svcagt_get_service_state(meshServiceName)) == 1)
                 {
                     if ((err = svcagt_set_service_state(meshServiceName, false)) != 0)
                         MeshInfo("In Opt mode MONITOR and mesh is disabled, mesh stop failed\n");
                 }
             }
             else
             {
                 MeshInfo("HCM RFC Status: Monitor , HCM Device Status: Monitor , Reason: NA\n");
                 Mesh_sendmeshWifiOptimization(mode);
             }
        break;
        case MESH_MODE_ENABLE:
            if (mesh_is_enabled)
            {
                MeshInfo("HCM RFC Status: Enable , HCM Device Status: %s , Reason: Mesh is Enabled\n",(g_pMeshAgent->meshWifiOptimizationMode==MESH_MODE_MONITOR?"Monitor":"Disable"));
            }
            else
            {
                //Mesh Disabled, also device mode is offline, so mesh should run in offline mode
                MeshInfo("HCM RFC Status: Enable , HCM Device Status: Enable , Reason: NA\n");
                if ((err = mesh_waitRestart()) != 0)
                {
                    MeshError("meshwifi service failed to start when mesh is disabled and mode is offline\n");
                }
            }
            isReserveModeActive = true;
        break;
        case MESH_MODE_DISABLE:
            if (mesh_is_enabled)
            {
                MeshInfo("Wifi optimization is send as OFF\n");
                Mesh_sendmeshWifiOptimization(mode);
            }
            else
            {
                MeshInfo("HCM RFC Status: Disable , HCM Device Status: %s , Reason: Mesh is Disabled\n",(g_pMeshAgent->meshWifiOptimizationMode==MESH_MODE_MONITOR?"Monitor":"Enable"));
                if ((err = svcagt_get_service_state(meshServiceName)) == 1)
                {
                    if ((err = svcagt_set_service_state(meshServiceName, false)) != 0)
                        MeshInfo("In Opt mode OFF and mesh is disabled, mesh stop failed\n");
                }
            }
        break;
        default:
            MeshInfo("Wrong device mode\n");
        break;
    }
}

/**
 * @brief Mesh Wifi Optimization mode
 *
 * This function will set 0 - off, 1 - monitor, 2 - offline
 */
bool Mesh_SetMeshWifiOptimizationMode(eWifiOptimizationMode uValue, bool init, bool commitSyscfg)
{
    int mode = uValue;

    if(is_bridge_mode_enabled() && (mode != MESH_MODE_DISABLE))
    {
        MeshInfo("Setting HCM mode is ignored since the Device is in Bridge Mode\n");
        return TRUE;
    }

    if((mode == MESH_MODE_MONITOR || mode == MESH_MODE_ENABLE) && (eth_mac_count >0))
    {
        MeshInfo("HCM Monitor/Enable Mode cant be configured if pod present, Ignoring rfc change\n");
        return TRUE;
    }

    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_SysCfgGetInt(meshSyncMsgArr[MESH_WIFI_OPT_MODE].sysStr) != mode)
    {
        MeshInfo("%s: mesh_wifi_optimization_mode: %d\n",__FUNCTION__,uValue);
        if(commitSyscfg) {
            if (syscfg_set_u_commit(NULL, meshSyncMsgArr[MESH_WIFI_OPT_MODE].sysStr, uValue) != 0)
                MeshError("Unable to set %s to :%d,\n",meshSyncMsgArr[MESH_WIFI_OPT_MODE].sysStr,uValue);
        }
        MeshWifiOptimizationHandle(uValue);
        g_pMeshAgent->meshWifiOptimizationMode = uValue;
    }
    return TRUE;
}

bool Mesh_SetReinitPeriod(int uValue, bool init, bool commitSyscfg)
{
    int mode = uValue;

    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_SysCfgGetInt(meshSyncMsgArr[MESH_WIFI_REINIT_PERIOD].sysStr) != mode)
    {
        MeshInfo("%s: meshReinitPeriod: %d\n",__FUNCTION__,uValue);
        if(commitSyscfg) {
            if (syscfg_set_u_commit(NULL, meshSyncMsgArr[MESH_WIFI_REINIT_PERIOD].sysStr, uValue) != 0)
                MeshError("Unable to set %s to :%d,\n",meshSyncMsgArr[MESH_WIFI_REINIT_PERIOD].sysStr,uValue);
        }
        g_pMeshAgent->meshReinitPeriod = uValue;
    }
    return TRUE;
}

/**
 * @brief Mesh Wifi Optimization mqtt broker
 *
 * This function will set ip
 */

bool Mesh_SetMeshWifiOptimizationMqttBroker(char *broker, bool init, bool commitSyscfg)
{

    static unsigned char out_val[128];
    errno_t rc = -1;
    int     ind      = -1;

    out_val[0]='\0';
    if( init || (Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_WIFI_OPT_BROKER].sysStr, out_val, sizeof(out_val)) == 0))
    {
        rc = strcmp_s(broker,strlen(broker),out_val,&ind);
        ERR_CHK(rc);
        if(((ind!=0) && (rc == EOK))||init)
        {
            if (commitSyscfg)
                Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_WIFI_OPT_BROKER].sysStr, broker, false);
            rc = strcpy_s(g_pMeshAgent->meshWifiOptMqttBroker, sizeof(g_pMeshAgent->meshWifiOptMqttBroker), broker);
            if(rc != EOK)
            {
               ERR_CHK(rc);
               MeshError("Error in copying broker to data model g_pMeshAgent->meshWifiOptMqttBroker\n");
            }
            if (g_pMeshAgent->meshWifiOptimizationMode != MESH_MODE_DISABLE)
                Mesh_sendmeshWifiMqtt(broker);
        }
    }
    return true;
}

/**
 * @brief Mesh Agent GREAcceleration Set Enable/Disable
 *
 * This function will enable/disable the GRE acceleration mode
 */
bool Mesh_SetGreAcc(bool enable, bool init, bool commitSyscfg)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled("mesh_gre_acc_enable") != enable)
    {
        MeshInfo("%s: GRE Acc Commit:%d, Enable:%d\n",
            __FUNCTION__, commitSyscfg, enable);
        if (enable && (!Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr) ||
            oneWifiEnabled || wanFailOverEnabled || Mesh_GetEnabled("mesh_ovs_enable") ||
            0 == access( OPENVSWITCH_LOADED, F_OK )))
        {   // mesh_ovs_enable has higher priority over mesh_gre_acc_enable,
            // therefore when ovs is enabled, disable gre acc.
            MeshWarning("Disabling GreAcc RFC, since OVS is currently enabled!\n");
            enable = false;
        }
        if (commitSyscfg && !meshSetGreAccSyscfg(enable))
        {
            MeshError("Unable to %s GreAcc RFC\n", (enable?"enable":"disable"));
            return false;
        }
        g_pMeshAgent->GreAccEnable = enable;

        //Send this as an RFC update to plume manager
        if(enable)
        {
            MeshInfo("GreAcc_RFC_changed_to_enabled\n");
        }
        else
        {
            MeshInfo("GreAcc_changed_to_disabled\n");
        }
        Mesh_sendRFCUpdate("GRE_ACC.Enable", enable ? "true" : "false", rfc_boolean);
    }
    return true;
}
/**
 * @brief Mesh Agent OpenvSwitch Set Enable/Disable
 *
 * This function will enable/disable the OpenvSwitch mode
 */
bool Mesh_SetOVS(bool enable, bool init, bool commitSyscfg)
{
    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled("mesh_ovs_enable") != enable)
    {
        MeshInfo("%s: OVS Enable Commit:%d, Enable:%d, XB3 Platform:%d\n",
            __FUNCTION__, commitSyscfg, enable, isXB3Platform);
        if (enable && isXB3Platform)
        {
            if (!Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr))
            {
                MeshWarning("Disabling OVS RFC, since mesh is currently disabled!\n");
                enable = false;
            }
            else if (Mesh_GetEnabled("mesh_gre_acc_enable"))
            {   // mesh_ovs_enable has higher priority over mesh_gre_acc_enable,
                // therefore disable Gre Acc.
                Mesh_SetGreAcc(false, false, true);
            }
        }
        if (commitSyscfg && !meshSetOVSSyscfg(enable))
        {
            MeshError("Unable to %s OVS RFC\n", (enable?"enable":"disable"));
            return false;
        }
        if (!enable)
        {
            MeshInfo("Disabling opensync since OVS is disabled\n");
            if (!Opensync_Set(false,false,commitSyscfg))
            {
                MeshError("Failed to disable Opensync\n");
            }
        }
        enable = enable || oneWifiEnabled || wanFailOverEnabled;
        g_pMeshAgent->OvsEnable = enable;

        //Send this as an RFC update to plume manager
        if(enable)
        {
            MeshInfo("OVS_RFC_changed_to_enabled\n");
        }
        else
        {
            MeshInfo("OVS_RFC_changed_to_disabled\n");
        }
        Mesh_sendRFCUpdate("OVS.Enable", enable ? "true" : "false", rfc_boolean);
    }
    return true;
}

bool Mesh_SetSMAPP(bool enable)
{
   return meshSet_sm_app_Syscfg(enable);
}

bool Mesh_SetXleAdaptiveFh(bool enable)
{
   Mesh_sendRFCUpdate("XleAdaptiveFhFeature.Enable", enable ? "true" : "false", rfc_boolean);
   return meshSet_XleAdaptiveFh_Syscfg(enable);
}

bool Mesh_SetSecureBackhaul(bool enable)
{
  if ( meshSet_SecureBackhaul_Syscfg(enable) == true ){
   Mesh_sendRFCUpdate("SecureBackhaul.Enable", enable ? "true" : "false", rfc_boolean);
   return true;
  }
   return false;
}

int getMeshErrorCode()
{
    return meshError;
}

#if 0
#ifdef MESH_OVSAGENT_ENABLE
static void Mesh_addOVSPort(char *ifname, char *bridge)
{
 //TODO: Stub to do recovery if OVS API fails
}
#endif
#endif

static void Mesh_ModifyPodTunnel(MeshTunnelSet *conf)
{
#ifdef MESH_OVSAGENT_ENABLE
    ovs_interact_request ovs_request = {0};
    Gateway_Config *pGwConfig = NULL;

    ovs_request.method = OVS_TRANSACT_METHOD;
    ovs_request.operation = OVS_INSERT_OPERATION;
    ovs_request.block_mode = OVS_ENABLE_BLOCK_MODE;

    ovs_request.table_config.table.id = OVS_GW_CONFIG_TABLE;

    if (!ovs_agent_api_get_config(OVS_GW_CONFIG_TABLE, (void **)&pGwConfig))
     {
        MeshError("%s failed to allocate and initialize config\n", __FUNCTION__);
        return ;
     }

    strncpy(pGwConfig->if_name, conf->ifname, sizeof(pGwConfig->if_name)-1);
    strncpy(pGwConfig->parent_bridge, conf->bridge, sizeof(pGwConfig->parent_bridge)-1);

    ovs_request.table_config.config = (void *) pGwConfig;

    if(ovs_agent_api_interact(&ovs_request,NULL))
     {
        MeshInfo("%s Mesh OVS interact succeeded ifname:%s bridge:%s\n",__FUNCTION__, conf->ifname, conf->bridge);
     } else {
        MeshError("%s Mesh OVS interact failed ifname:%s bridge:%s\n",__FUNCTION__, conf->ifname, conf->bridge);
     }

#else
    UNREFERENCED_PARAMETER(conf);
    MeshInfo("%s: OVSAgent is not integrated in this platform yet\n", __FUNCTION__);
#endif
}

static void Mesh_ModifyPodTunnelVlan(MeshTunnelSetVlan *conf, bool is_ovs)
{
#ifdef MESH_OVSAGENT_ENABLE
    if (is_ovs)
    {
        ovs_interact_request ovs_request = {0};
        Gateway_Config *pGwConfig = NULL;
        ovs_request.method = OVS_TRANSACT_METHOD;
        ovs_request.operation = OVS_INSERT_OPERATION;
        ovs_request.block_mode = OVS_ENABLE_BLOCK_MODE;
        ovs_request.table_config.table.id = OVS_GW_CONFIG_TABLE;

        if (!ovs_agent_api_get_config(OVS_GW_CONFIG_TABLE, (void **)&pGwConfig))
        {
           MeshError("%s failed to allocate and initialize config\n", __FUNCTION__);
           return ;
        }

        strncpy(pGwConfig->if_name, conf->ifname, sizeof(pGwConfig->if_name)-1);
        strncpy(pGwConfig->parent_bridge, conf->bridge, sizeof(pGwConfig->parent_bridge)-1);
        if(conf->vlan > 0) {
            strncpy(pGwConfig->parent_ifname, conf->parent_ifname, sizeof(pGwConfig->parent_ifname)-1);
            pGwConfig->vlan_id = conf->vlan;
            pGwConfig->if_type = OVS_VLAN_IF_TYPE;
        }
        ovs_request.table_config.config = (void *) pGwConfig;

        if(ovs_agent_api_interact(&ovs_request,NULL))
        {
            MeshInfo("%s Mesh OVS interact succeeded ifname:%s bridge:%s\n",__FUNCTION__, conf->ifname, conf->bridge);
        } else {
            MeshError("%s Mesh OVS interact failed ifname:%s bridge:%s\n",__FUNCTION__, conf->ifname, conf->bridge);
        }

    }
#ifdef WAN_FAILOVER_SUPPORTED
    else
        Mesh_CreatePodVlan(conf);
#endif
#else
    UNREFERENCED_PARAMETER(conf);
    MeshInfo("%s: OVSAgent is not integrated in this platform yet\n", __FUNCTION__);
#endif
}

bool Opensync_Set(bool enable, bool init, bool commitSyscfg) {
    if (init || Mesh_GetEnabled("opensync") != enable)
    {
        if(enable && !Mesh_GetEnabled("mesh_ovs_enable")) {
            MeshInfo("OVS is disabled. Enabling OVS before enabling opensync\n");
            if(!Mesh_SetOVS(true,false,commitSyscfg))
            {
                MeshError("Facing error while trying to enable OVS\n");
                return false;
            }
        }
        if (commitSyscfg && !OpensyncSetSyscfg(enable) ) {
            MeshError("Unable to %s Opensync\n", enable?"enable":"disable");
	    return false;
        }
        enable = enable || oneWifiEnabled || wanFailOverEnabled;
        g_pMeshAgent->OpensyncEnable = enable;
        //Send this as an RFC update to plume manager
        if(enable) {
            MeshInfo("Opensync_RFC_changed_to_enabled\n");
	    MeshInfo("Opensync will be effective after reboot\n");
	}
        else
        {
            MeshInfo("Opensync_RFC_changed_to_disabled\n");
	}
        Mesh_sendRFCUpdate("Opensync.Enable", enable ? "true" : "false", rfc_boolean);
    }
    return TRUE;
}

void* handleMeshEnable(void *Args)
{
	bool success = TRUE;
        bool enable = FALSE;
	unsigned char outBuf[128];
        static bool last_set = FALSE;
        int error = MB_OK;
        int err = 0;
        unsigned char bit_mask = (UCHAR) ( (intptr_t)Args); 
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
	if(is_uplink_tid_exist)
	{
            MeshInfo("handleMeshEnable is skipped due to is_uplink_tid_exist enable\n");
	    return NULL;
        }
#endif
        pthread_mutex_lock(&mesh_handler_mutex);
        enable = (bit_mask & 0x02) ? TRUE : FALSE;
        if (bit_mask & 0x01)
        {
            pthread_detach(pthread_self());
        }
        MeshInfo("last_set= %d, enable = %d\n",last_set,enable);
        if(last_set == enable)
        {
            MeshInfo("Skipping mesh redundant set\n");
            meshError = MB_OK;
            pthread_mutex_unlock(&mesh_handler_mutex);
            return NULL;
        }

     bool is_meshenable_waiting = false;
	 if (enable) {
            // This will only work if this service is started *AFTER* CcspWifi
            // If the service is not running, start it
            if(is_bridge_mode_enabled()) {
              MeshError("Mesh Pre-check conditions failed, setting mesh wifi to disabled since the Device is in Bridge Mode\n");
              error =  MB_ERROR_PRECONDITION_FAILED;
              meshSetSyscfg(0, true);
              pthread_mutex_unlock(&mesh_handler_mutex);
              return NULL;
            }
            if(!radio_check()){
                  MeshError("Mesh Radio's are down, wait and check for the radio's to be up\n");
                  is_meshenable_waiting = true;
            }
	    if(is_band_steering_enabled()) {
                   if(set_wifi_boolean_enable("Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable", "false")==FALSE) {
                        MeshError(("MESH_ERROR:Fail to enable Mesh because fail to turn off Band Steering\n"));
                        error =  MB_ERROR_BANDSTEERING_ENABLED;
                        meshSetSyscfg(0, true);
                        pthread_mutex_unlock(&mesh_handler_mutex);
                        return NULL;
                   }
            }

            MeshInfo("Checking if Mesh APs are enabled or disabled\n");
            if(is_SSID_enabled())
                MeshInfo("Mesh interfaces are up\n");
            else
            {
                MeshInfo("Turning Mesh SSID enable\n");
                set_mesh_APs(true);
            }
            // Check if the is_meshenable_waiting is true, before starting the mesh services
            if ((!is_meshenable_waiting) && (err = svcagt_get_service_state(meshServiceName)) == 0)
            {
                // returns "0" on success
                if ((err = mesh_waitRestart()) != 0)
                {
                    MeshError("meshwifi service failed to run, igonoring the mesh enablement\n");
		    t2_event_d("WIFI_ERROR_meshwifiservice_failure", 1);
                    error = MB_ERROR_MESH_SERVICE_START_FAIL;
                    meshSetSyscfg(0, true);
                    success = FALSE;
                }
            }
            else if ((!is_meshenable_waiting) && (((err = svcagt_get_service_state(meshServiceName)) == 1)&&(isReserveModeActive)))
            {
                if ((err = mesh_waitRestart()) != 0)
                {
                    MeshError("meshwifi service failed to run in reserve mode, igonoring the mesh enablement\n");
                    success = FALSE;
                }
                if (g_pMeshAgent->meshWifiOptimizationMode != MESH_MODE_ENABLE)
                    isReserveModeActive = false;
                else
                   MeshInfo("MWO Reserve mode: mwo will enter into offline mode when mesh gets disabled\n");
            }
            else
                MeshInfo("Not supported\n");

         } else {
            // This will only work if this service is started *AFTER* CcspWifi
            // If the service is running, stop it
            if ((err = svcagt_get_service_state(meshServiceName)) == 1)
            {
                bool bridge_mode_enabled = is_bridge_mode_enabled();
                //Check for reserve mode, if in reserve mode restart opensync
                if (isReserveModeActive && (g_pMeshAgent->meshWifiOptimizationMode == MESH_MODE_ENABLE) && (!bridge_mode_enabled))
                {
                    if ((err = mesh_waitRestart()) != 0)
                    {
                        MeshError("meshwifi service failed to run in reserve mode, igonoring the mesh enablement\n");
                        success = FALSE;
                    }
                    if (g_pMeshAgent->meshWifiOptimizationMode != MESH_MODE_ENABLE)
                        isReserveModeActive = false;
                }
                else
                {
                    // returns "0" on success
                    if (bridge_mode_enabled)
                    {
                        isReserveModeActive = false;
                        g_pMeshAgent->meshWifiOptimizationMode = MESH_MODE_DISABLE;
                        Mesh_SetMeshWifiOptimizationMode(MESH_MODE_DISABLE, false, true);
                    }
                    if ((err = svcagt_set_service_state(meshServiceName, false)) != 0)
                    {
                        meshSetSyscfg(0, true);
                        error = MB_ERROR_MESH_SERVICE_STOP_FAIL;
                        success = FALSE;
                    }
                }
            }
        }

        if (success) {
            //MeshInfo("Meshwifi has been %s\n",(enable?"enabled":"disabled"));
            MeshInfo("MESH_STATUS:%s\n",(enable?"enabled":"disabled"));//

            // Update the data model
            if (!((g_pMeshAgent->meshStatus == MESH_WIFI_STATUS_FULL) && enable))
            {
                g_pMeshAgent->meshStatus = (enable?MESH_WIFI_STATUS_INIT:MESH_WIFI_STATUS_OFF);
                // Send sysevent notification
                /*Coverity Fix CID:69958 DC.STRING_BUFFER */
                snprintf(outBuf,sizeof(outBuf), "MESH|%s", (enable?"true":"false"));
                Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, outBuf, 0, true);
                /*Coverity Fix CID:69958 DC.STRING_BUFFER */
                snprintf(outBuf,sizeof(outBuf), "MESH|%s", meshWifiStatusArr[(enable?MESH_WIFI_STATUS_INIT:MESH_WIFI_STATUS_OFF)].mStr);
                Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_STATUS].sysStr, outBuf, 0, true);
            }
            else
               MeshInfo("Skipped MESH_WIFI_STATUS change since this is just meshAgent restart\n");

            g_pMeshAgent->meshEnable = enable;
	    last_set = enable;
            Mesh_InitEthHost_Sync();
            MeshInfo("Update the active client list by triggering EthHost_Sync\n");
        } else {
            MeshError("Error %d %s Mesh Wifi\n", err, (enable?"enabling":"disabling"));
            if ((err == 0x100) && (enable == TRUE)) {
            	t2_event_d("SYS_INFO_MESHWIFI_DISABLED", 1);
	    }
        }
   if (!(bit_mask & 0x01))
   {
       meshError = error;
   }
   pthread_mutex_unlock(&mesh_handler_mutex);
   return NULL;
}

/**
 * @brief Mesh Agent Set Enable/Disable
 *
 * This function will enable/disable the Mesh service
 */
bool Mesh_SetEnabled(bool enable, bool init, bool commitSyscfg)
{
    // MeshInfo("Entering into %s\n",__FUNCTION__);
    bool success = true;
    unsigned char bit_mask = 1;

    // If the enable value is different or this is during setup - make it happen.
    if (init || Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr) != enable)
    {
        if (!enable && isXB3Platform)
        {   // if mesh is being disabled, then also disable ovs
            MeshWarning("Disabling OVS and GRE_ACC RFC, since mesh will be disabled!\n");
            Mesh_SetOVS(false, false, true);
            Mesh_SetGreAcc(false,false,true);
        }
        meshSetSyscfg(enable, commitSyscfg);
 	pthread_t tid;
        if(enable)
        {
            bit_mask = bit_mask | 0x2;
        }
	pthread_create(&tid, NULL, handleMeshEnable, (void*)(intptr_t)bit_mask);

    }

    return success;
}

BOOL is_radio_enabled(char *dcs1, char *dcs2)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char *dstComponent = "eRT.com.cisco.spvtg.ccsp.wifi";
    char *dstPath = "/com/cisco/spvtg/ccsp/wifi";
    char *paramNames[]={dcs1,dcs2};
    int  valNum = 0;
    BOOL ret_b=FALSE;
    errno_t rc = -1;
    int ind = -1;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            2,
            &valNum,
            &valStructs);

    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s CcspBaseIf_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }

    MeshWarning("valStructs[0]->parameterValue = %s valStructs[1]->parameterValue = %s \n",valStructs[0]->parameterValue,valStructs[1]->parameterValue);
    rc = strcmp_s("false",strlen("false"),valStructs[0]->parameterValue,&ind);
    ERR_CHK(rc);
    if((ind ==0 ) && (rc == EOK)) 
        dcs1[0]=0;
    else
	ret_b=TRUE;

    rc = strcmp_s("false",strlen("false"),valStructs[1]->parameterValue,&ind);
    ERR_CHK(rc);
    if((ind ==0 ) && (rc == EOK)) 
        dcs2[0]=0;
    else
        ret_b=TRUE;

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return ret_b;
}

#if 0
static BOOL is_DCS_enabled(void)
{
    if(is_radio_enabled("Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable","Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable") 
          || is_radio_enabled("Device.WiFi.Radio.1.X_COMCAST-COM_DCSEnable","Device.WiFi.Radio.2.X_COMCAST-COM_DCSEnable")) 
    {
        return TRUE;
    }
    return FALSE;
}
#endif

/**
 * This is a last option if all syscfg and retrial fails
 *
 */
static void Mesh_Recovery(void)
{
    if(!access(MESH_ENABLED, F_OK)) {
     MeshInfo("mesh flag is enabled in nvram, setting mesh enabled\n");
     Mesh_SetEnabled(true, true, true);
    } else
    {
     MeshInfo("mesh flag not found in nvram, setting mesh disabled\n");
     Mesh_SetEnabled(false, true, true);
    }
}
/**
 * @brief Mesh Agent set default values
 *
 * This function will fetch and set the default values for the mesh agent.
 *
 */
static void Mesh_SetDefaults(ANSC_HANDLE hThisObject)
{
    unsigned char out_val[128] = {'\0'};
    errno_t rc = -1, rc1 = -1;
    int     ind = -1, ind1 = -1;
    int i = 0;
    FILE *cmd=NULL;
    char mesh_enable[16];
    bool isPartnerURL = false;

    PCOSA_DATAMODEL_MESHAGENT pMyObject = (PCOSA_DATAMODEL_MESHAGENT) hThisObject;

    // Check to see if the mesh dev flag is set
    bool devFlag = (access(meshDevFile, F_OK) == 0);
    //Fetch device name, this temporary fix should be removed when RDKB-31468 ticket is fixed
    is_xf3_xb3_platform();
    // set URL
    out_val[0]='\0';
    if( ( isPartnerURL = Mesh_getPartnerBasedURL(out_val)) || ( !Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, out_val, sizeof(out_val)))) {
        rc = strcmp_s(out_val, strlen(out_val), urlOld, &ind);
        ERR_CHK(rc);
        if (!devFlag && ((ind == 0) && (rc == EOK)))
        {
            // Using the old value, reset to new default
            MeshInfo("Mesh url was using old value, updating to %s\n", urlDefault);
            Mesh_SetUrl((char *)urlDefault, true);
        }
        else
        {
            if (devFlag) {
                MeshInfo("Mesh dev specified, url not changed %s\n", out_val);
            } else {
                MeshInfo("Mesh url is %s\n", out_val);
            }
            unsigned char outBuf[136];
            rc = strcpy_s(pMyObject->meshUrl, sizeof(pMyObject->meshUrl), out_val);
            if(rc != EOK)
            {
                ERR_CHK(rc);
                MeshError("Error in copying Mesh url to pMyObject->meshUrl\n");
                return;
            }
            // Send sysevent notification
            /* Coverity Fix CID:65429 DC.STRING_BUFFER */
            snprintf(outBuf,sizeof(outBuf), "MESH|%s", out_val);
            if( isPartnerURL)
                Mesh_SysCfgSetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, out_val, false);
            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_URL_CHANGE].sysStr, outBuf, 0, false);
        }
    }
    else
    {
        MeshInfo("Mesh Url not set, using default %s\n", urlDefault);
        Mesh_SetUrl((char *)urlDefault, true);
    }

    // set Mesh State
    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_STATE_CHANGE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting initial mesh state to Full\n");
        Mesh_SetMeshState(MESH_STATE_FULL, true, true);
    }
    else
    {
        rc = strcmp_s(out_val, strlen(out_val), meshStateArr[MESH_STATE_FULL].mStr, &ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
            MeshInfo("Setting initial mesh state to Full\n");
            Mesh_SetMeshState(MESH_STATE_FULL, true, false);
        }
        else
        {
            rc = strcmp_s(out_val, strlen(out_val), meshStateArr[MESH_STATE_MONITOR].mStr, &ind);
            ERR_CHK(rc);
            if((ind == 0) && (rc == EOK))
            {
                MeshInfo("Setting initial mesh state to Monitor\n");
                Mesh_SetMeshState(MESH_STATE_MONITOR, true, false);
            }
            else
            {
                MeshWarning("Incorrect Mesh State value in syscfg, setting to Full\n");
                Mesh_SetMeshState(MESH_STATE_FULL, true, true);
            }
        }
    }

    // Set Mesh enabled
    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg get mesh_enable failed Retrying 5 times\n");
        for(i=0; i<5; i++)
        {
          if(!Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr, out_val, sizeof(out_val)))
          {
              MeshInfo("Syscfg get passed in %d retrial\n", i+1);
              t2_event_d("SYS_INFO_SYSCFG_get_passed",  1);
              rc = strcmp_s("true",strlen("true"),out_val,&ind);
              ERR_CHK(rc);
              if((ind == 0 ) && (rc == EOK))
              {
                  Mesh_SetEnabled(true, true, true);
              }
              else
              {
                  rc = strcmp_s("false",strlen("false"),out_val,&ind);
                  ERR_CHK(rc);
                  if((ind == 0 ) && (rc == EOK))
                  {
                     MeshInfo("Setting initial mesh wifi to disabled\n");
                     Mesh_SetEnabled(false, true, true);
                  }
                  else
                      Mesh_Recovery();
              }
              break;
          }
          else
           MeshInfo("Syscfg get failed in %d retrial\n", i+1);
        }
        if(i==5) {
         MeshInfo("All retrial failed for syscfg get , try reading from syscfg.db before applying default\n");
         t2_event_d("SYS_ERROR_SyscfgGet_retry_failed", 1);
         cmd=v_secure_popen("r", "grep mesh_enable /nvram/secure/data/syscfg.db | cut -d '=' -f2"); 
         if (cmd==NULL) {
             cmd=v_secure_popen("r", "grep mesh_enable /opt/secure/data/syscfg.db | cut -d '=' -f2"); 
             if(cmd==NULL) {
                MeshInfo("Error opening syscfg.db file, do final attempt for recovery\n");
         	t2_event_d("SYS_ERROR_SYSCFG_Open_failed", 1);
                Mesh_Recovery();
             }
             else
                v_secure_pclose(cmd);
         }
        else
        {
           fgets(mesh_enable, sizeof(mesh_enable), cmd);
           MeshInfo("Manual Reading from db file = %s\n",mesh_enable);
           rc = strcmp_s("true",strlen("true"),mesh_enable,&ind);
           ERR_CHK(rc);
           rc1 = strcmp_s("false",strlen("false"),mesh_enable,&ind1);
           ERR_CHK(rc1);
           if(((ind ==0 ) && (rc == EOK))) {
               Mesh_SetEnabled(true, true, true);
           }
           else if (((ind1 == 0) && (rc1 == EOK))) {
               Mesh_SetEnabled(false, true, true);
           }
           else
           {
               MeshInfo("mesh_enable returned null from syscfg.db final attempt for recovery\n");
               t2_event_d("SYS_ERROR_ApplyDefaut_MeshStatus", 1);
               Mesh_Recovery();
           }
           v_secure_pclose(cmd);
         }
       }
    } else {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK)){
            Mesh_SetEnabled(true, true, false);
        }
        else {
            rc = strcmp_s("false",strlen("false"),out_val,&ind);
            ERR_CHK(rc);
            if((ind == 0) && (rc == EOK)){
                MeshInfo("Setting initial mesh wifi default to disabled\n");
               Mesh_SetEnabled(false, true, false);
            }
            else {
            MeshInfo("Unexpected value from syscfg , doing recovery\n");
            Mesh_Recovery();
           }
       }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_RFC_UPDATE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting Ethbhaul mode to default FALSE\n");
        Mesh_SetMeshEthBhaul(false,true,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind ==0 ) && (rc == EOK))
        {
           MeshInfo("Setting initial ethbhaul mode to true\n");
           Mesh_SetMeshEthBhaul(true,true,false);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind ==0 ) && (rc == EOK))
           {
               MeshInfo("Setting initial ethbhaul mode to false\n");
               Mesh_SetMeshEthBhaul(false,true,false);
           }
           else
           {
               MeshInfo("Ethernet Bhaul status error from syscfg , setting default FALSE\n");
               Mesh_SetMeshEthBhaul(false,true,true);
           }
        }
    }

    int mode_val;
    mode_val = Mesh_SysCfgGetInt(meshSyncMsgArr[MESH_WIFI_OPT_MODE].sysStr);
    MeshInfo("Syscfg get, MESH_WIFI_OPT_MODE : %d\n",mode_val);
    if(mode_val  == 0)
    {
        MeshInfo("Syscfg, Setting MESH_WIFI_OPT_MODE to default OFF\n");
        Mesh_SetMeshWifiOptimizationMode(MESH_MODE_DISABLE, false, true);
    }
    else
    {
        if(is_bridge_mode_enabled())
        {
            MeshInfo("Device is in Bridge mode, Setting hcm mode to Disable\n");
            Mesh_SetMeshWifiOptimizationMode(MESH_MODE_DISABLE, false, true);
        }
        else
            Mesh_SetMeshWifiOptimizationMode(mode_val, true, false);
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_WIFI_OPT_BROKER].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting any default value for mqtt brocker: %s\n",MQTT_LOCAL_MQTT_BROKER);
        Mesh_SetMeshWifiOptimizationMqttBroker(MQTT_LOCAL_MQTT_BROKER,true,true);
    }
    else
    {
        Mesh_SetMeshWifiOptimizationMqttBroker(out_val,true,false);
    }

    int reinit_val;
    reinit_val = Mesh_SysCfgGetInt(meshSyncMsgArr[MESH_WIFI_REINIT_PERIOD].sysStr);
    MeshInfo("Syscfg get, MESH_WIFI_REINIT_PERIOD : %d\n",reinit_val);
    if(reinit_val  == 0)
    {
        MeshInfo("Syscfg, Setting MESH_WIFI_REINIT_PERIOD to default 2\n");
        Mesh_SetReinitPeriod(2, true, true);
    }
    else
    {
        Mesh_SetReinitPeriod(reinit_val, true, false);
    }

#ifdef ONEWIFI
    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_XLE_MODE_CLOUD_CTRL_RFC].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting Xle Mode Cloud Ctrl Enable mode to default FALSE\n");
        Mesh_SetXleModeCloudCtrlEnable(false,true,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind ==0 ) && (rc == EOK))
        {
           MeshInfo("Setting initial Xle Mode Cloud Ctrl Enable mode to true\n");
           Mesh_SetXleModeCloudCtrlEnable(true,true,false);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind ==0 ) && (rc == EOK))
           {
               MeshInfo("Setting initial Xle Mode Cloud Ctrl Enable mode to false\n");
               Mesh_SetXleModeCloudCtrlEnable(false,true,false);
           }
           else
           {
               MeshInfo("Xle Mode CloudCtrl Enable status error from syscfg , setting default FALSE\n");
               Mesh_SetXleModeCloudCtrlEnable(false,true,true);
           }
        }
    }
#endif
    out_val[0]='\0';

    if(Mesh_SysCfgGetStr("opensync", out_val, sizeof(out_val)) != 0)
    {
        out_val[0]='\0';
        if(Mesh_SysCfgGetStr("opensync_enable", out_val, sizeof(out_val)) != 0)
        {
            MeshInfo("Syscfg error, Setting opensync mode to default\n");
            Opensync_Set(false,true,true);
        }
        else
        {
            rc = strcmp_s("true",strlen("true"),out_val,&ind);
            ERR_CHK(rc);
            if((ind ==0 ) && (rc == EOK))
            {
                MeshInfo("Setting initial Opensync mode to true - LEGACY\n");
                Opensync_Set(true,true,true);
            }
            else
            {
                MeshInfo("Setting initial Opensync mode to false - LEGACY\n");
                Opensync_Set(false,true,true);
            }
        }
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind ==0 ) && (rc == EOK)) {
           MeshInfo("Setting initial Opensync mode to true\n");
           Opensync_Set(true,true,true);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
	   ERR_CHK(rc);
	   if((ind ==0 ) && (rc == EOK)) {
               MeshInfo("Setting initial Opensync mode to false\n");
               Opensync_Set(false,true,true);
	   } else {
               Opensync_Set(false,true,true);
               MeshInfo("Opensync status error from syscfg , setting default\n");

	   }
        }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr("mesh_ovs_enable", out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting OVS mode to default\n");
        Mesh_SetOVS(false,true,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
           MeshInfo("Setting initial OVS mode to true\n");
           Mesh_SetOVS(true,true,false);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
           {
              MeshInfo("Setting initial OVS mode to false\n");
              Mesh_SetOVS(false,true,false);
           }
           else
           {
              MeshInfo("OVS status error from syscfg , setting default\n");
              Mesh_SetOVS(false,true,true);
           }
        }
    }

    out_val[0]='\0';
    if (Mesh_SysCfgGetStr("mesh_security_legacy", out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting mesh_security_legacy to default\n");
        Mesh_SetSecuritySchemaLegacy(true, true, true);
    }
    else
    {
        rc = strcmp_s("true", strlen("true"), out_val, &ind);
        ERR_CHK(rc);
        if ((ind == 0) && (rc == EOK))
        {
            MeshInfo("Setting initial mesh_security_legacy to true\n");
            Mesh_SetSecuritySchemaLegacy(true, true, false);
        }
        else
        {
            rc = strcmp_s("false", strlen("false"), out_val, &ind);
            ERR_CHK(rc);
            if ((ind == 0) && (rc == EOK))
            {
                MeshInfo("Setting initial mesh_security_legacy to false\n");
                Mesh_SetSecuritySchemaLegacy(false, true, false);
            }
            else
            {
                MeshInfo("mesh_security_legacy error, setting default\n");
                Mesh_SetSecuritySchemaLegacy(true, true, true);
            }
        }
    }

    out_val[0]='\0';
    if (Mesh_SysCfgGetStr("mesh_cache", out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting Cache Status to default\n");
        Mesh_SetCacheStatus(false, true, true);
    }
    else
    {
        rc = strcmp_s("true", strlen("true"), out_val, &ind);
        ERR_CHK(rc);
        if ((ind == 0) && (rc == EOK))
        {
            MeshInfo("Setting initial Cache Status to true\n");
            Mesh_SetCacheStatus(true, true, false);
        }
        else
        {
            rc = strcmp_s("false", strlen("false"), out_val, &ind);
            ERR_CHK(rc);
            if ((ind == 0) && (rc == EOK))
            {
                MeshInfo("Setting initial Cache Status to false\n");
                Mesh_SetCacheStatus(false, true, false);
            }
            else
            {
                MeshInfo("Cache Status error, setting default\n");
                Mesh_SetCacheStatus(false, true, true);
            }
        }
    }

    out_val[0]='\0';
    if (Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_RECORDER_ENABLE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting recorder to default\n");
        Recorder_SetEnable(false, true, true);
    }
    else
    {
        rc = strcmp_s("true", strlen("true"), out_val, &ind);
        ERR_CHK(rc);
        if ((ind == 0) && (rc == EOK))
        {
            MeshInfo("Setting initial recorder state to true\n");
            Recorder_SetEnable(true, true, false);
        }
        else
        {
            rc = strcmp_s("false", strlen("false"), out_val, &ind);
            ERR_CHK(rc);
            if ((ind == 0) && (rc == EOK))
            {
                MeshInfo("Setting initial recorder state to false\n");
                Recorder_SetEnable(false, true, false);
            }
            else
            {
                MeshInfo("Recorder state error, setting default\n");
                Recorder_SetEnable(false, true, true);
            }
        }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_CA_CERT].sysStr, out_val, sizeof(out_val)) != 0)
    {   
        MeshInfo("Syscfg error, Setting %s  to default false\n",meshSyncMsgArr[MESH_CA_CERT].sysStr);
        Mesh_SetMeshCaCert(false,true,true);
    }
    else
    {   
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {  
           MeshInfo("Setting %s from persistent storage value true\n",meshSyncMsgArr[MESH_CA_CERT].sysStr);
           Mesh_SetMeshCaCert(true,true,false);
        }
        else
        {  
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
           {  
              MeshInfo("Setting %s from persistent storage value false\n",meshSyncMsgArr[MESH_CA_CERT].sysStr);
              Mesh_SetMeshCaCert(false,true,false);
           }
           else
           {
              MeshInfo("Error, Setting %s  to default false\n",meshSyncMsgArr[MESH_CA_CERT].sysStr);
              Mesh_SetMeshCaCert(false,true,true);
           }
        }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_DSCP_INHERIT_ENABLE].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting %s  to default false\n",meshSyncMsgArr[MESH_DSCP_INHERIT_ENABLE].sysStr);
        Mesh_SetMeshDscpInheritKernelModule(false,true,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
           MeshInfo("Setting %s from persistent storage value true\n",meshSyncMsgArr[MESH_DSCP_INHERIT_ENABLE].sysStr);
           Mesh_SetMeshDscpInheritKernelModule(true,true,false);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
           {
              MeshInfo("Setting %s from persistent storage value false\n",meshSyncMsgArr[MESH_DSCP_INHERIT_ENABLE].sysStr);
              Mesh_SetMeshDscpInheritKernelModule(false,true,false);
           }
           else
           {
              MeshInfo("Error, Setting %s  to default false\n",meshSyncMsgArr[MESH_DSCP_INHERIT_ENABLE].sysStr);
              Mesh_SetMeshDscpInheritKernelModule(false,true,true);
           }
        }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr(meshSyncMsgArr[MESH_REDUCED_RETRY].sysStr, out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting optimized mesh retry to default\n");
        Mesh_SetMeshRetryOptimized(true,true,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
           MeshInfo("Setting initial optimized mesh retry mode to true\n");
           Mesh_SetMeshRetryOptimized(true,true,false);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
           {
              MeshInfo("Setting initial optimized mesh retry mode to false\n");
              Mesh_SetMeshRetryOptimized(false,true,false);
           }
           else
           {
              MeshInfo("optimized mesh retry error from syscfg , setting default\n");
              Mesh_SetMeshRetryOptimized(false,true,true);
           }
        }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr("hcm_recording_upload_enable", out_val, sizeof(out_val)) != 0) {
        MeshInfo("Syscfg error, Setting hcm_recording_upload_enable mode to default true\n");
        Recorder_UploadEnable(true,true,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
           MeshInfo("Setting initial hcm_recording_upload_enable mode to true\n");
           Recorder_UploadEnable(true,true,false);
        }
        else
        {
            rc = strcmp_s("false",strlen("false"),out_val,&ind);
            ERR_CHK(rc);
            if((ind == 0) && (rc == EOK))
            {
               MeshInfo("Setting initial hcm_recording_upload_enable mode to false\n");
               Recorder_UploadEnable(false,true,false);
            }
            else
            {
               MeshInfo("hcm_recording_upload_enable status error from syscfg , setting default true\n");
               Recorder_UploadEnable(true,true,true);
            }
        }
    }

    out_val[0]='\0';
    if(Mesh_SysCfgGetStr("mesh_hd_recommendation_enable", out_val, sizeof(out_val)) != 0)
    {
        MeshInfo("Syscfg error, Setting mesh_hd_recommendation_enable mode to default true\n");
        Mesh_SetHDRecommendationEnable(true,true,true);
    }
    else
    {
        rc = strcmp_s("true",strlen("true"),out_val,&ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK))
        {
           MeshInfo("Setting initial mesh_hd_recommendation_enable mode to true\n");
           Mesh_SetHDRecommendationEnable(true,true,false);
        }
        else
        {
           rc = strcmp_s("false",strlen("false"),out_val,&ind);
           ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
           {
              MeshInfo("Setting initial mesh_hd_recommendation_enable mode to false\n");
              Mesh_SetHDRecommendationEnable(false,true,false);
           }
           else
           {
              MeshInfo("mesh_hd_recommendation_enable status error from syscfg , setting default true\n");
              Mesh_SetHDRecommendationEnable(true,true,true);
           }
        }
    }

    if(isXB3Platform)
    {
        out_val[0]='\0';
        if(Mesh_SysCfgGetStr("mesh_gre_acc_enable", out_val, sizeof(out_val)) != 0)
        {
           MeshInfo("Syscfg error, Setting gre acc mode to default\n");
           Mesh_SetGreAcc(false,true,true);
        }
        else
        {
           rc = strcmp_s("true",strlen("true"),out_val,&ind);
           ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
           {
              MeshInfo("Setting initial gre acc mode to true\n");
              Mesh_SetGreAcc(true,true,false);
           }
           else
           {
              rc = strcmp_s("false",strlen("false"),out_val,&ind);
              ERR_CHK(rc);
              if((ind == 0) && (rc == EOK))
              {
                 MeshInfo("Setting initial gre acc mode to false\n");
                 Mesh_SetGreAcc(false,true,false);
              }
              else
              {
                 MeshInfo("gre acc status error from syscfg , setting default\n");
                 Mesh_SetGreAcc(false,true,true);
              }
           }
        }
    }

    g_pMeshAgent->XleAdaptiveFh_Enable = Mesh_GetEnabled_State("XleAdaptiveFh_State");
    g_pMeshAgent->SecureBackhaul_Enable = Mesh_GetSecureBackhaul_Enable("SecureBackhaul_Enable");

    //setting SM_APP disble state
    out_val[0]='\0';
    if(Mesh_SysCfgGetStr("sm_app_disable", out_val, sizeof(out_val)) == 0)
    {
        rc = strcmp_s("false",strlen("false"),out_val,&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
          g_pMeshAgent->SM_Disable = false;
          return;
        }
    }
    Mesh_SetSMAPP(true);
    g_pMeshAgent->SM_Disable = true;
    // MeshInfo("Exiting from %s\n",__FUNCTION__);
}


/**
 * @brief Mesh Agent Update Connected Device
 *
 * This function will update the connected device table and notify
 * Mesh of changes
 */
bool Mesh_UpdateConnectedDevice(char *mac, char *iface, char *host, char *status)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    errno_t rc[2] = {-1, -1};
    int ind[2] = {-1, -1};

    // Notify plume
    // Set sync message type
    if( Mesh_PodAddress(mac, FALSE)) {
        /** Update Eth Bhaul SM **/
        if( (strcmp(status, "Offline") == 0) && (strcmp(iface, "Ethernet") == 0) ) {
            meshHandleEvent(mac, POD_DC_EVENT);
        }
     MeshInfo("Skipping pod connect event to plume cloud | mac=%s\n", mac);
     return false;
    }
    mMsg.msgType = MESH_CLIENT_CONNECT;
    if (mac != NULL && mac[0] != '\0') {
        rc[0] = strcpy_s(mMsg.data.meshConnect.mac, sizeof(mMsg.data.meshConnect.mac), mac);
        if(rc[0] != EOK)
        {
            ERR_CHK(rc[0]);
            MeshError("Error in copying mac to Connected Client\n");
            return false;
        }
    } else {
        MeshWarning("Mac address is NULL in connected client message, ignoring\n");
        return false;
    }

    if (status != NULL && status[0] != '\0') {
        rc[0] = strcmp_s("Connected",strlen("Connected"),status,&ind[0]);
        ERR_CHK(rc[0]);
        rc[1] = strcmp_s("Online",strlen("Online"),status,&ind[1]);
        ERR_CHK(rc[1]);
        mMsg.data.meshConnect.isConnected = ((((ind[0] == 0) && (rc[0] == EOK)) || ((ind[1] == 0) && (rc[1] == EOK)))? true:false);
    } else {
        MeshWarning("Connect status is NULL in connected client message, ignoring\n");
        return false;
    }

    if (iface != NULL && iface[0] != '\0') {
        mMsg.data.meshConnect.iface = Mesh_IfaceLookup(iface);
    } else {
        MeshWarning("Interface is NULL in connected client message, ignoring\n");
        return false;
    }

    if (host != NULL && host[0] != '\0') {
        rc[0] = strcpy_s(mMsg.data.meshConnect.host, sizeof(mMsg.data.meshConnect.host), host);
        if(rc[0] != EOK)
        {
            ERR_CHK(rc[0]);
            MeshError("Error in copying host to connected client\n");
            return false;
        }
    }
    // update our connected device table
    Mesh_UpdateClientTable(mMsg.data.meshConnect.iface, mMsg.data.meshConnect.mac, mMsg.data.meshConnect.host, mMsg.data.meshConnect.isConnected);

    // We filled our data structure so we can send it off
    msgQSend(&mMsg);

    return true;
}
/**
 * @brief Mesh Agent rfc sendReducedRetry  to plume managers
 *
 * This function will notify plume agent about RFC changes
 */
static void Mesh_sendReducedRetry(bool value)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    // Notify plume manager cm
    // Set sync message type
    mMsg.msgType = MESH_REDUCED_RETRY;
    mMsg.data.retryFlag.isenabled = value;
    msgQSend(&mMsg);
}

/**
 * @brief Mesh Agent rfc sendWifiMotionEnable  to plume managers
 *
 * This function will notify opensync when wifi motion rfc recieved
 */
void Mesh_sendWifiMotionEnable(bool value)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    // Notify plume manager cm
    // Set sync message type
    mMsg.msgType =     MESH_WIFI_MOTION;
    mMsg.data.meshwifiMotion.isenabled = value;
    msgQSend(&mMsg);
}

/**
 * @brief Mesh Agent send mesh wifi optimization mode  to plume managers
 *
 * This function will send mesh wifi optimization mode
 * disabled = 0, monitor = 1, offline = 2,
 */
static void Mesh_sendmeshWifiOptimization(eWifiOptimizationMode mode)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    // Notify plume manager cm
    // Set sync message type
    mMsg.msgType = MESH_WIFI_OPT_MODE;
    mMsg.data.meshwifiOpt.mode = mode;
    msgQSend(&mMsg);
}


/**
 * @brief Mesh Agent send mesh wifi optimization mode to plume managers
 *
 * This function will send local mqtt broker info
 */
static void Mesh_sendmeshWifiMqtt( char *val)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    char *token;
    char *delim = ":";
    char *contextStr = NULL;
    bool valFound = false;
    int idx = 0;
    int rc = 0;

    token = strtok_r(val, delim, &contextStr);
    while( token != NULL)
    {
        switch (idx)
        {
            case 0:
                rc = strcpy_s(mMsg.data.meshwifiOptMqttBroker.ip, sizeof(mMsg.data.meshwifiOptMqttBroker.ip), token);
                if(rc != EOK)
                {
                   ERR_CHK(rc);
                   MeshError("Error in copying mqtt broker ip\n");
                }
                else
                    valFound = true;
                break;

            case 1:
                mMsg.data.meshwifiOptMqttBroker.port = strtol(token,NULL,10);
                valFound = true;
                break;

             default:
               break;
        }
        token = strtok_r(NULL, delim,&contextStr);
        idx++;
    }
    contextStr = NULL;
    // Notify plume manager qm, to reconnect if to new mqtt broker
    // if wifi opt mode is monitor
    // Set sync message type
    mMsg.msgType = MESH_WIFI_OPT_BROKER;
    if (valFound)
        msgQSend(&mMsg);
}

#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
static void Mesh_sendEbhStatusRequest()
{
    // send out notification to plume
    MeshSync mMsg = {0};
    // Notify plume manager cm 
    // Set sync message type
    mMsg.msgType = MESH_EBH_INFO;
    mMsg.data.ebhStatus.enabled = 1;
    MeshInfo(("Get ebhStatus Mesh_sendEbhStatusRequest.\n"));
    msgQSend(&mMsg);
}
#endif
#if defined(ONEWIFI)

/**
 * @brief Mesh Agent send sta interface name to plume managers
 *
 * This function will notify plume agent about sta interface
 */
void Mesh_sendStaInterface(char * mesh_sta, char *bssid,  bool status)
{
    MeshSync mMsg = {0};
    int rc = 0;

    // Set sync message type
    mMsg.msgType = MESH_WIFI_EXTENDER_MODE;
    mMsg.data.onewifiXLEExtenderMode.status  = status ?  1 : 0;
    mMsg.data.onewifiXLEExtenderMode.isStatusSet = 1;
    mMsg.data.onewifiXLEExtenderMode.device_mode = 0;
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    if (device_mode != DEFAULT_MODE)
        mMsg.data.onewifiXLEExtenderMode.device_mode |= (device_mode == GATEWAY_MODE)? TARGET_GW_TYPE:TARGET_EXTENDER_TYPE;
#endif
    if (bssid)
    {
        rc = strcpy_s(mMsg.data.onewifiXLEExtenderMode.bssid,
             sizeof(mMsg.data.onewifiXLEExtenderMode.bssid), bssid);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            MeshError("Error in copying bss id\n");
        }
    }
    if(mesh_sta)
    {
        rc = strcpy_s(mMsg.data.onewifiXLEExtenderMode.InterfaceName,
             sizeof(mMsg.data.onewifiXLEExtenderMode.InterfaceName), mesh_sta);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            MeshError("Error in copying Interface name\n");
        }
    }
    MeshInfo("Sysevent set  MESH_WIFI_EXTENDER_MODE interface %s\n",mMsg.data.onewifiXLEExtenderMode.InterfaceName);
    Mesh_SyseventSetStr(meshSyncMsgArr[MESH_WIFI_EXTENDER_MODE].sysStr, mMsg.data.onewifiXLEExtenderMode.InterfaceName, 0, false);
    msgQSend(&mMsg);
}
#endif

/**
 * @brief Mesh Agent Send RFC parameter to plume managers
 *
 * This function will notify plume agent about RFC changes
 */
static void Mesh_sendRFCUpdate(const char *param, const char *val, eRfcType type)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    errno_t rc = -1;
    // Notify plume
    // Set sync message type
    mMsg.msgType = MESH_RFC_UPDATE;
    rc = strcpy_s(mMsg.data.rfcUpdate.paramname, sizeof(mMsg.data.rfcUpdate.paramname),  param);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        MeshError("Error in copying paramname for RFC Update\n");
        return;
    }
    rc = strcpy_s(mMsg.data.rfcUpdate.paramval, sizeof(mMsg.data.rfcUpdate.paramval), val);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        MeshError("Error in copying paramval for RFC Update\n");
        return;
    }
    mMsg.data.rfcUpdate.type = type;
    MeshInfo("RFC_UPDATE: param: %s val:%s type=%d\n",mMsg.data.rfcUpdate.paramname, mMsg.data.rfcUpdate.paramval, mMsg.data.rfcUpdate.type);
    if (!msgQSend(&mMsg))
    {
        MeshInfo("RFC_UPDATE: Failed param: %s val:%s type=%d\n",mMsg.data.rfcUpdate.paramname, mMsg.data.rfcUpdate.paramval, mMsg.data.rfcUpdate.type);
    }
}

/**
 * @brief Mesh Agent Sync DHCP lease
 *
 * This function will notify plume agent to process the dnsmasq.lease
 * file
 */
static void Mesh_sendDhcpLeaseSync(void)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    //Setting the MSB of clientSocketsMask as state m/c to make sure we dont send any dnsmasq lease updates to
    //plume while dnsmasq.lease sync is happening
    clientSocketsMask |= (1 << MAX_CONNECTED_CLIENTS);
    //copy the dnsmasq.leases file from ARM to Atom and send out SYNC message to use the file
    if(isXB3Platform) {
        MeshInfo("Copying dnsmasq.leases file from ARM to Atom for the first time\n");
        v_secure_system("/usr/ccsp/wifi/synclease.sh");
    }
#if 1

    // Notify plume
    // Set sync message type
    MeshInfo("Sending Mesh sync lease notification to plume agent\n");
    mMsg.msgType = MESH_DHCP_RESYNC_LEASES;
    msgQSend(&mMsg);
    //umask the MSB so that , we can go ahead sending dnsmasq lease notifications
    clientSocketsMask &= ~(1 << MAX_CONNECTED_CLIENTS);
#endif
}

/**
 * @brief Mesh Agent Sync DHCP lease
 *
 * This function will notify plume agent if any change in the
 * lease
 */
static void Mesh_sendDhcpLeaseUpdate(int msgType, char *mac, char *ipaddr, char *hostname, char *fingerprint)
{
    // send out notification to plume
    MeshSync mMsg = {0};
    errno_t rc = -1;
    // Notify plume
    // Set sync message type
    mMsg.msgType = msgType;
    if(clientSocketsMask && msgType <= MESH_DHCP_UPDATE_LEASE)
    {
       rc = strcpy_s(mMsg.data.meshLease.mac, sizeof(mMsg.data.meshLease.mac), mac);
       if(rc != EOK)
       {
           ERR_CHK(rc);
           MeshError("Error in copying mac address for DHCP lease update, mac - %s\n", mac);
           return;
       }
       rc = strcpy_s(mMsg.data.meshLease.ipaddr, sizeof(mMsg.data.meshLease.ipaddr), ipaddr);
       if(rc !=EOK)
       {
          ERR_CHK(rc);
          MeshError("Error in copying ip address for DHCP lease update, mac - %s\n", mac);
          return;
       }
       rc = strcpy_s(mMsg.data.meshLease.hostname, sizeof(mMsg.data.meshLease.hostname), hostname);
       if(rc !=EOK)
       {
           ERR_CHK(rc);
           MeshError("Error in copying hostname for DHCP lease update, mac - %s\n", mac);
           return;
       }
       rc = strcpy_s(mMsg.data.meshLease.fingerprint, sizeof(mMsg.data.meshLease.fingerprint), fingerprint);
       if(rc !=EOK)
       {
           ERR_CHK(rc);
           MeshError("Error in copying fingerprint for DHCP lease update, mac - %s\n", mac);
           return;
       }
       MeshInfo("DNSMASQ: %d %s %s %s %s\n",mMsg.msgType,mMsg.data.meshLease.mac, mMsg.data.meshLease.ipaddr, mMsg.data.meshLease.hostname, mMsg.data.meshLease.fingerprint);
       msgQSend(&mMsg);
       // Link change notification: prints telemetry on pod networks
       if( msgType != MESH_DHCP_REMOVE_LEASE && Mesh_PodAddress(mac, FALSE) && strstr( ipaddr, POD_IP_PREFIX)) {
          Mesh_logLinkChange();
       }

    }
}

/**
 * @brief Mesh Agent register system events
 *
 * This function will register the sysevents.
 *
 */
static bool Mesh_Register_sysevent(ANSC_HANDLE hThisObject)
{
    bool status = false;
    const int max_retries = 6;
    int retry = 0;
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    do
    {
        sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "meshAgent", &sysevent_token);
        if (sysevent_fd < 0)
        {
            MeshError("meshAgent failed to register with sysevent daemon\n");
            status = false;
        }
        else
        {
            MeshInfo("meshAgent registered with sysevent daemon successfully\n");
            status = true;
        }

        //Make another connection for gets/sets
        sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "meshAgent-gs", &sysevent_token_gs);
        if (sysevent_fd_gs < 0)
        {
            MeshError("meshAgent-gs failed to register with sysevent daemon\n");
            status = false;
        }
        else
        {
            MeshInfo("meshAgent-gs registered with sysevent daemon successfully\n");
            status = true;
        }

        if(status == false) {
            v_secure_system("/usr/bin/syseventd");
            sleep(5);
        }
    }while((status == false) && (retry++ < max_retries));


    if (status != false)
       Mesh_SetDefaults(hThisObject);

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return status;
}


/**************************************************************************/
/*! \fn void *Mesh_sysevent_handler(void *data)
 **************************************************************************
 *  \brief Function to process sysevent event
 *  \return 0
**************************************************************************/
static void *Mesh_sysevent_handler(void *data)
{
    UNREFERENCED_PARAMETER(data);
    // MeshInfo("Entering into %s\n",__FUNCTION__);

    async_id_t wifi_init_asyncid;
    async_id_t wifi_ssidName_asyncid;
    async_id_t wifi_ssidChanged_asyncid;
    async_id_t wifi_offChanEnable_asyncid;
#ifdef ONEWIFI
    async_id_t onewifi_xle_extender_mode_asyncid;
#endif
    async_id_t wifi_ssidAdvert_asyncid;
    async_id_t wifi_radio_channel_asyncid;
    async_id_t wifi_radio_channel_mode_asyncid;
    async_id_t wifi_radio_operating_std_asyncid;
    async_id_t wifi_apSecurity_asyncid;
    async_id_t wifi_apKickDevice_asyncid;
    async_id_t wifi_apKickAllDevice_asyncid;
    async_id_t wifi_apAddDevice_asyncid;
    async_id_t wifi_apDelDevice_asyncid;
    async_id_t wifi_macAddrControl_asyncid;
    async_id_t subnet_cfg_asyncid;
    async_id_t mesh_status_asyncid;
    async_id_t mesh_enable_asyncid;
    async_id_t mesh_url_asyncid;
    async_id_t wifi_txRate_asyncid;
#ifdef WAN_FAILOVER_SUPPORTED
    async_id_t mesh_wfo_enabled_asyncid;
#endif
    async_id_t wifi_dynamic_profile_asyncid;
    async_id_t mesh_firewall_restart_asyncid;

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_RESET].sysStr,                     TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_RESET].sysStr,                     &wifi_init_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_NAME].sysStr,                 TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_NAME].sysStr,                 &wifi_ssidName_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_CHANGED].sysStr,              TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_CHANGED].sysStr,              &wifi_ssidChanged_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_OFF_CHAN_ENABLE].sysStr,           TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_OFF_CHAN_ENABLE].sysStr,           &wifi_offChanEnable_asyncid);
#ifdef ONEWIFI
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_EXTENDER_MODE].sysStr,              TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_EXTENDER_MODE].sysStr,              &onewifi_xle_extender_mode_asyncid);
#endif
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_ADVERTISE].sysStr,            TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_SSID_ADVERTISE].sysStr,            &wifi_ssidAdvert_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL_MODE].sysStr,        TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL_MODE].sysStr,        &wifi_radio_channel_mode_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_OPERATING_STD].sysStr,       TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_OPERATING_STD].sysStr,       &wifi_radio_operating_std_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL].sysStr,             TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_RADIO_CHANNEL].sysStr,             &wifi_radio_channel_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_SECURITY].sysStr,               TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_SECURITY].sysStr,               &wifi_apSecurity_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ASSOC_DEVICE].sysStr,      TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ASSOC_DEVICE].sysStr,      &wifi_apKickDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES].sysStr, TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES].sysStr, &wifi_apKickAllDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_ADD_ACL_DEVICE].sysStr,         TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_ADD_ACL_DEVICE].sysStr,         &wifi_apAddDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_DEL_ACL_DEVICE].sysStr,         TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_AP_DEL_ACL_DEVICE].sysStr,         &wifi_apDelDevice_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_MAC_ADDR_CONTROL_MODE].sysStr,     TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_MAC_ADDR_CONTROL_MODE].sysStr,     &wifi_macAddrControl_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_SUBNET_CHANGE].sysStr,                  TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_SUBNET_CHANGE].sysStr,                  &subnet_cfg_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_STATUS].sysStr,                  TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_STATUS].sysStr,                  &mesh_status_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr,                  TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr,                  &mesh_enable_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_URL_CHANGE].sysStr,                   TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_URL_CHANGE].sysStr,                   &mesh_url_asyncid);

    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_TXRATE].sysStr,                   TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_TXRATE].sysStr,                   &wifi_txRate_asyncid);
#ifdef WAN_FAILOVER_SUPPORTED
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WFO_ENABLED].sysStr,                     TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WFO_ENABLED].sysStr,                     &mesh_wfo_enabled_asyncid);
#endif
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_WIFI_DYNAMIC_PROFILE].sysStr,           TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_WIFI_DYNAMIC_PROFILE].sysStr,           &wifi_dynamic_profile_asyncid);
    sysevent_set_options(sysevent_fd,     sysevent_token, meshSyncMsgArr[MESH_FIREWALL_START].sysStr,                     TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, meshSyncMsgArr[MESH_FIREWALL_START].sysStr,                     &mesh_firewall_restart_asyncid);
    for (;;)
    {
        unsigned char name[64], val[256];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        char *contextStr = NULL;
        async_id_t getnotification_asyncid;
        errno_t rc       = -1;
        int     ind      = -1;

        // Tell the socket code we are ready to handle messages
        if (!s_SysEventHandler_ready) {
            s_SysEventHandler_ready = true;
        }

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_asyncid);

        if (err)
        {
        	// this is actually a catastrophic error, but we are going to kill some time here
        	// hoping that selfheal will re-start the syseventd process and we can recover.
            MeshError("sysevent_getnotification failed with error: %d\n", err);
            sleep(120);
        }
        else
        {
            eMeshSyncType ret_val=0;
            if(Get_MeshSyncType(name,&ret_val))
            {
                if (ret_val == MESH_WIFI_RESET)
                {
                     if( val[0] != '\0')
                         MeshInfo("received notification event %s val =%s \n", name, val);
                     else
                         MeshInfo("received notification event %s\n", name);
                         // Need to restart the meshwifi service if it is currently running.
                         if ((g_pMeshAgent->meshEnable || svcagt_get_service_state(meshServiceName)))
                         {
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
                     if(!is_uplink_tid_exist)
                     {
#endif
#if defined WAN_FAILOVER_SUPPORTED
                                 if(!wfo_mode)
                                 {
#endif
                                     MeshSync mMsg = {0};

                                     // Set sync message type
                                     mMsg.msgType = MESH_WIFI_RESET;
                                     mMsg.data.wifiReset.reset = true;

                                     // We filled our data structure so we can send it off
                                     msgQSend(&mMsg);

                                     /**
                                     * At this time, we are just restarting the mesh components when a wifi_init comes
                                     * in. At some point in the future, they may handle the wifi_init directly rather
                                     * than having to be re-started.
                                     */
                                     // shutdown
                                     if ( val[0] != '\0' && g_pMeshAgent->meshEnable)
                                     {
                                         rc = strcmp_s("start", strlen("start"), val, &ind);
                                         if((rc == EOK) && (!ind))
                                         {
                                             MeshInfo("Stopping meshwifi service\n");
                                             svcagt_set_service_state(meshServiceName, false);
                                         }
                                         else
                                         {
                                             rc = strcmp_s("stop", strlen("stop"), val, &ind);
                                             if((rc == EOK) && (!ind))
                                             {
                                                 MeshInfo("Starting meshwifi service\n");
                                                 svcagt_set_service_state(meshServiceName, true);
                                             }
                                             else
                                                 MeshWarning("Unsupported option %s \n", val);
                                         }
                                     }
#if defined WAN_FAILOVER_SUPPORTED
                                 } else {
                                     MeshInfo("Skip wifi reset while in WFO mode\n");
                                 }
#endif
#if !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
                    }
#endif
                         }
                         else {
                             MeshInfo("meshwifi.service is not running - not restarting\n");
                         }
            }
            else if (ret_val == MESH_WIFI_RADIO_CHANNEL)
            {
                // Radio config sysevents will be formatted: ORIG|index|channel
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_RADIO_CHANNEL;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiRadioChannel.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("channel=%s\n", token);
                            mMsg.data.wifiRadioChannel.channel = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim,&contextStr);
                        idx++;
                    }
                    contextStr = NULL;
                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_RADIO_CHANNEL_MODE)
            {
                // Radio config sysevents will be formatted: ORIG|index|channel
                if (val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_RADIO_CHANNEL_MODE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiRadioChannelMode.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("channeModel=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiRadioChannelMode.channelMode, sizeof(mMsg.data.wifiRadioChannelMode.channelMode), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying channel mode in MESH_WIFI_RADIO_CHANNEL_MODE\n");
                            }
                            else
                            {
                                valFound = true;
                            }
                            break;
                        case 3:
                            MeshInfo("gOnlyFlag=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiRadioChannelMode.gOnlyFlag = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        case 4:
                            MeshInfo("nOnlyFlag=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiRadioChannelMode.nOnlyFlag = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        case 5:
                            MeshInfo("acOnlyFlag=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiRadioChannelMode.acOnlyFlag = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }

                    contextStr = NULL;
                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_RADIO_OPERATING_STD)
            {
                if (val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    mMsg.msgType = MESH_WIFI_RADIO_OPERATING_STD;
                    token = strtok_r(val, delim, &contextStr);
                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiRadioChannelMode.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("Operating Standard=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiRadioChannelMode.channelMode,
                                    sizeof(mMsg.data.wifiRadioChannelMode.channelMode), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying Operating Standard\n");
                            }
                            else
                            {
                                valFound = true;
                            }
                        default:
                            break;
                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        msgQSend(&mMsg);
                    }
                }
            }

            else if (ret_val == MESH_WIFI_SSID_ADVERTISE)
            {
                // SSID config sysevents will be formatted: ORIG|index|ssid
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_SSID_ADVERTISE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiSSIDAdvertise.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("enable=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiSSIDAdvertise.enable = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_SSID_NAME)
            {
                // SSID config sysevents will be formatted: ORIG|index|ssid
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_SSID_NAME;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiSSIDName.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            /*Coverity Fix CID:57710 PW.TOO_MANY_PRINTF_ARGS */
                            MeshInfo("ssid reveived:\n");
                            rc = strcpy_s(mMsg.data.wifiSSIDName.ssid, sizeof(mMsg.data.wifiSSIDName.ssid), token);
                            if(rc != EOK)
                            {
                                  ERR_CHK(rc);
                                  MeshError("Error in copying WiFI ssid\n");
                            }
                            else{
                                 valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_SSID_CHANGED)
            {
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = g_pMeshAgent->OpensyncEnable?MESH_WIFI_SSID_CHANGED:MESH_WIFI_SSID_NAME;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiSSIDChanged.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            /*Coverity Fix CID:57710 PW.TOO_MANY_PRINTF_ARGS */
                            mMsg.data.wifiSSIDChanged.enable = g_pMeshAgent->OpensyncEnable?strtol(token,NULL,10):0;
                            valFound = true;
                            break;
                        case 3:
                            MeshInfo("ssid received:%s\n", token);
                            if(g_pMeshAgent->OpensyncEnable)
                            {
                                rc = strcpy_s(mMsg.data.wifiSSIDChanged.ssid, sizeof(mMsg.data.wifiSSIDChanged.ssid), token);
                            }
                            else
                            {
                                rc = strcpy_s(mMsg.data.wifiSSIDName.ssid, sizeof(mMsg.data.wifiSSIDName.ssid), token);
                            }
                            if(rc != EOK)
                            {
                                  ERR_CHK(rc);
                                  MeshError("Error in copying WiFI ssid\n");
                            }
                            else
                            {
                                 valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_OFF_CHAN_ENABLE)
            {
                MeshError("Received MESH_WIFI_OFF_CHAN_ENABLE Notification\n");
                if ( val[0] != '\0')
                {
                     MeshInfo("off_channel_enable=%s\n", val);
                     if (((rc = strcmp_s("true", strlen("true"), val, &ind)) == EOK) && (ind == 0))
                     {
                         g_offchanEnabled = true;
                     }
                     else if (((rc = strcmp_s("false", strlen("false"), val, &ind)) == EOK) && (ind == 0))
                     {
                         g_offchanEnabled = false;
                     }
                     ERR_CHK(rc);

                     g_offchanvalFound = true;
                }
                off_chan_scan_status_set();
            }
#ifdef ONEWIFI
            else if (ret_val == MESH_WIFI_EXTENDER_MODE)
            {
		if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_EXTENDER_MODE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("Interface \n");
                            rc = strcpy_s(mMsg.data.onewifiXLEExtenderMode.InterfaceName, sizeof(mMsg.data.onewifiXLEExtenderMode.InterfaceName), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying sta interface name\n");
                            }
                            else{
                                MeshInfo("mMsg.data.onewifiXLEExtenderMode.InterfaceName: %s\n",mMsg.data.onewifiXLEExtenderMode.InterfaceName);
                                valFound = true;
                            }
                            break;
                        case 2:
                            MeshInfo("Bssid \n");
                            rc = strcpy_s(mMsg.data.onewifiXLEExtenderMode.bssid, sizeof(mMsg.data.onewifiXLEExtenderMode.bssid), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying bssid name\n");
                            }
                            else{
				MeshInfo("mMsg.data.onewifiXLEExtenderMode.bssid: %s\n",mMsg.data.onewifiXLEExtenderMode.bssid);
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
#endif
            else if (ret_val == MESH_WIFI_AP_SECURITY)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_SECURITY;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                           
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPSecurity.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                             /* Coverity Issue Fix - CID:125245 : Printf Args */
                            MeshInfo("passphrase recieved \n");
                            rc = strcpy_s(mMsg.data.wifiAPSecurity.passphrase, sizeof(mMsg.data.wifiAPSecurity.passphrase), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying passphrase\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        case 3:
                             /* Coverity Issue Fix - CID:125245 : Printf Args*/
                            MeshInfo("security mode received\n");
                            rc = strcpy_s(mMsg.data.wifiAPSecurity.secMode, sizeof(mMsg.data.wifiAPSecurity.secMode), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying security mode\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        case 4:
                             /* Coverity Issue Fix - CID:125245  : Printf Args*/
                            MeshInfo("encryption mode recieved\n");
                            rc = strcpy_s(mMsg.data.wifiAPSecurity.encryptMode, sizeof(mMsg.data.wifiAPSecurity.encryptMode), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying encryption mode\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_KICK_ASSOC_DEVICE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_KICK_ASSOC_DEVICE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPKickAssocDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("mac=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiAPKickAssocDevice.mac, sizeof(mMsg.data.wifiAPKickAssocDevice.mac), token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying mac address - MESH_WIFI_AP_KICK_ASSOC_DEVICE\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPKickAllAssocDevices.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_ADD_ACL_DEVICE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_ADD_ACL_DEVICE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPAddAclDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("mac=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiAPAddAclDevice.mac, sizeof(mMsg.data.wifiAPAddAclDevice.mac), token);
                            if(rc != EOK)
                            {
                                  ERR_CHK(rc);
                                  MeshError("Error in copying mac address - MESH_WIFI_AP_ADD_ACL_DEVICE\n");
                            }
                            else{
                                  valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_AP_DEL_ACL_DEVICE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_AP_DEL_ACL_DEVICE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPDelAclDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("mac=%s\n", token);
                            rc = strcpy_s(mMsg.data.wifiAPDelAclDevice.mac, sizeof(mMsg.data.wifiAPDelAclDevice.mac), token);
                            if(rc != EOK)
                            {
                                 ERR_CHK(rc);
                                 MeshError("Error in copying mac address - MESH_WIFI_AP_DEL_ACL_DEVICE\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_MAC_ADDR_CONTROL_MODE)
            {
                // AP config sysevents will be formatted: ORIG|index|passphrase|secMode|encryptMode
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_MAC_ADDR_CONTROL_MODE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiAPKickAssocDevice.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                            MeshInfo("isEnabled=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiMacAddrControlMode.isEnabled = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        case 3:
                            MeshInfo("isBlacklist=%s\n", token);
                            rc = strcmp_s("true",strlen("true"),token,&ind);
                            ERR_CHK(rc);
                            (mMsg.data.wifiMacAddrControlMode.isBlacklist = ((ind == 0) && (rc == EOK)) ? 1:0);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_STATUS)
            {
                // mesh sysevents will be formatted: ORIG|mode
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    eMeshWifiStatusType status = MESH_WIFI_STATUS_OFF;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process MESH status sysevent messages
                            rc = strcmp_s("MESH", strlen("MESH"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("mesh_status=%s\n", token);
                            rc = strcmp_s("Init", strlen("Init"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind == 0) && (rc == EOK)) {
				t2_event_d("WIFI_INFO_MeshInit", 1);
  			    }
                            status = Mesh_WifiStatusLookup(token);
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound && (status == MESH_WIFI_STATUS_FULL || status == MESH_WIFI_STATUS_MONITOR)) {
                        MeshInfo("Mesh is in Full/Monitor Mode\n");
                    }
                }
            }
            else if (ret_val == MESH_WIFI_ENABLE)
            {
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    bool enabled = false;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("mesh_enable=%s\n", token);
                            rc = strcmp_s("true", strlen("true"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind == 0) && (rc == EOK))
                            {
                                enabled = true;
                            }
                            valFound = true;
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        if(enabled==true)
                        {
                            if(is_bridge_mode_enabled())// || is_band_steering_enabled() || is_DCS_enabled())
                            {
                                enabled = false;
                            }
                        }
                        // We filled our data structure so we can send it off
                        Mesh_SetEnabled(enabled, false, true);
                    }
                }
            }
            else if (ret_val == MESH_URL_CHANGE)
            {
                // mesh url changed
                // Url config sysevents will be formatted: ORIG|url
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    char url[128] = {0};

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("url=%s\n", token);
                            rc = strcpy_s(url, sizeof(url),token);
                            if(rc != EOK)
                            {
                                ERR_CHK(rc);
                                MeshError("Error in copying url in MESH_URL_CHANGE\n");
                            }
                            else{
                                valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        Mesh_SetUrl(url, false);
                    }
                }
            }
            else if (ret_val == MESH_SUBNET_CHANGE)
            {
                // mesh subnet change changed
                // Subnet change config sysevents will be formatted: ORIG|gwIP|netmask
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_SUBNET_CHANGE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("gwIP=%s\n", token);
                            rc = strcpy_s(mMsg.data.subnet.gwIP, sizeof(mMsg.data.subnet.gwIP),token);
                            if(rc != EOK)
                            {
                                 ERR_CHK(rc);
                                 MeshError("Error in copying gwIP in MESH_SUBNET_CHANGE\n");
                            }
                            else{
                                 valFound = true;
                            }
                            break;
                        case 2:
                            MeshInfo("netmask=%s\n", token);
                            rc = strcpy_s(mMsg.data.subnet.netmask, sizeof(mMsg.data.subnet.netmask),token);
                            if(rc != EOK)
                            {
                                 ERR_CHK(rc);
                                 MeshError("Error in copying netmask in MESH_SUBNET_CHANGE\n");
                            }
                            else{
                                 valFound = true;
                            }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
            else if (ret_val == MESH_WIFI_TXRATE)
            {
                // TxRate config sysevents will be formatted: ORIG|index|BasicRates:<basicRates>|OperationalRates:<operationalRates>
                if ( val[0] != '\0')
                {
                    char *delim = "|";
                    char *token;
                    int idx = 0;
                    bool valFound = false;
                    bool process = true;
                    MeshSync mMsg = {0};

                    // Set sync message type
                    mMsg.msgType = MESH_WIFI_TXRATE;

                    // grab the first token
                    token = strtok_r(val, delim, &contextStr);

                    while( token != NULL && process)
                    {
                        switch (idx)
                        {
                        case 0:
                            // Parse message origin to see if we should process.
                            // We only process RDK sysevent messages
                            rc = strcmp_s("RDK", strlen("RDK"), token, &ind);
                            ERR_CHK(rc);
                            if ((ind != 0) && (rc == EOK))
                            {
                                process = false;
                                continue;
                            } else {
                                MeshInfo("received notification event %s\n", name);
                            }
                            break;
                        case 1:
                            MeshInfo("index=%s\n", token);
                            mMsg.data.wifiTxRate.index = strtol(token,NULL,10);
                            valFound = true;
                            break;
                        case 2:
                        {
                            // We need to strip off the qualifier "BasicRates:" from the front of the string
                            char *strPtr = strchr(token, ':');

                            if (strPtr != NULL) {
                                MeshInfo("basicRates=%s\n", (strPtr+1));
                                rc = strcpy_s(mMsg.data.wifiTxRate.basicRates, sizeof(mMsg.data.wifiTxRate.basicRates), (strPtr+1));
                                if(rc != EOK)
                                {
                                     ERR_CHK(rc);
                                     MeshError("Error in copying WiFi basicRates in MESH_WIFI_TXRATE\n");
                                }
                            } else {
                                // we couldn't find our qualifier, just copy the whole thing
                                MeshInfo("basicRates=%s\n", token);
                                rc = strcpy_s(mMsg.data.wifiTxRate.basicRates, sizeof(mMsg.data.wifiTxRate.basicRates), token);
                                if(rc != EOK)
                                {
                                     ERR_CHK(rc);
                                     MeshError("Error in copying Whole qualifier WiFi basicRates in MESH_WIFI_TXRATE\n");
                                }
                            }
                            if(rc == EOK)
                            {
                                  valFound = true;
                            }
                        }
                            break;
                        case 3:
                        {
                            // We need to strip off the qualifier "OperationalRates:" from the front of the string
                            char *strPtr = strchr(token, ':');

                            if (strPtr != NULL) {
                                MeshInfo("operationalRates=%s\n", (strPtr+1));
                                rc = strcpy_s(mMsg.data.wifiTxRate.opRates, sizeof(mMsg.data.wifiTxRate.opRates), (strPtr+1));
                                if(rc != EOK)
                                {
                                    ERR_CHK(rc);
                                    MeshError("Error in copying WiFi opRates in MESH_WIFI_TXRATE\n");
                                } 
                            } else {
                                // we couldn't find our qualifier, just copy the whole thing
                                MeshInfo("operationalRates=%s\n", token);
                                rc = strcpy_s(mMsg.data.wifiTxRate.opRates, sizeof(mMsg.data.wifiTxRate.opRates), token);
                                if(rc != EOK)
                                {
                                    ERR_CHK(rc);
                                    MeshError("Error in copying Whole qualifier WiFi opRates in MESH_WIFI_TXRATE\n");
                                }
                            }
                            if(rc == EOK)
                            {
                                 valFound = true;
                            }
                        }
                            break;
                        default:
                            break;

                        }
                        token = strtok_r(NULL, delim, &contextStr);
                        idx++;
                    }
                    contextStr = NULL;

                    if (valFound) {
                        // We filled our data structure so we can send it off
                        msgQSend(&mMsg);
                    }
                }
            }
#if defined(WAN_FAILOVER_SUPPORTED)
            else if (ret_val == MESH_WFO_ENABLED)
            {
                if ( val[0] != '\0')
                {
                    MeshInfo("received sysevent MESH_WFO_ENABLED:%s\n",val);
                    if(!strncmp(val,"true",sizeof("true")))
                    {
                        wfo_mode = true;
                        Send_MESH_WFO_ENABLED_Msg(true);
                    }
                    else if(!strncmp(val,"false",sizeof("false")))
                    {
                        wfo_mode = false;
                        Send_MESH_WFO_ENABLED_Msg(false);
                    }
                    else
                    {
                        wfo_mode = false;
                        MeshInfo("Unknow value for MESH_WFO_ENABLED");
                    }
                }

            }
#endif //WAN_FAILOVER_SUPPORTED
            else if (ret_val == MESH_WIFI_DYNAMIC_PROFILE)
            {
                if (val[0] != '\0')
                {
                    MeshInfo("received sysevent MESH_WIFI_DYNAMIC_PROFILE:%s", val);
                    MeshSync mMsg = {0};
                    mMsg.msgType = MESH_WIFI_DYNAMIC_PROFILE;
                    mMsg.data.wifiDynamicProfile.profile_id = strtol(val,NULL,10);
                    msgQSend(&mMsg);
                }
            }
            else if (ret_val == MESH_FIREWALL_START)
            {
                if ( val[0] != '\0')
                {
                    int count = 0, index = 0, dscp_marking;
                    bool mac_changed = false;
                    char dscp_cmd[MAX_BUF_SIZE] = {0};
                    char dscp_value[MAX_BUF_SIZE] = {0};
                    int rc = -1;

                    if (strncmp(val,"started", 7) == 0)
                    {
                        syscfg_get(NULL, "DCPC_PrioClients_Count", dscp_value, sizeof(dscp_value));
                        count = atoi(dscp_value);

                        if ( count != mac_index  && mac_index )
                            mac_changed = true;

                        mac_index =  count;
                        while (count--)
                        {
                            if (index < MAX_MACS)
                            {
                                snprintf(dscp_cmd, sizeof(dscp_cmd), "DCPC_PrioClients_Mac_%d", count + 1);
                                if (syscfg_get(NULL, dscp_cmd, dscp_value, sizeof(dscp_value)) == 0 && strlen(dscp_value) != 0)
                                {
                                    if(g_pMeshAgent->IsdscpConfigEnabled)
                                    {
                                        if(strncmp(dscp_mac_list.mac_addresses[index],dscp_value,MAC_SIZE))
                                            mac_changed = true;
                                    }
                                    strncpy(dscp_mac_list.mac_addresses[index], dscp_value, sizeof(dscp_mac_list.mac_addresses[index]) - 1);
                                    dscp_mac_list.mac_addresses[index][sizeof(dscp_mac_list.mac_addresses[index]) - 1] = '\0';

                                    snprintf(dscp_cmd, sizeof(dscp_cmd), "DCPC_PrioClients_DSCP_%d", count + 1);
                                    if (syscfg_get(NULL, dscp_cmd, dscp_value, sizeof(dscp_value)) == 0 && strlen(dscp_value) != 0)
                                    {
                                        dscp_marking = atoi(dscp_value);
                                        if(g_pMeshAgent->IsdscpConfigEnabled)
                                        {
                                            if(dscp_mac_list.dscp_value[index] != dscp_marking)
                                                mac_changed = true;
                                        }
                                        dscp_mac_list.dscp_value[index] = dscp_marking;
                                        index++;
                                    }
                                }
                            }
                        }
                        if (( mac_index != 0) && (mac_changed || !g_pMeshAgent->IsdscpConfigEnabled))
                        {
                            if(g_pMeshAgent->IsdscpConfigEnabled && g_pMeshAgent->dscpInheritRfcEnable && g_pMeshAgent->IsPodConnect)
                            {
                                MeshInfo("xmeshgre.ko module is running so deleting..\n");
                                rc= v_secure_system("systemctl stop greinheritance.service");
                                if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
                                    MeshError("systemctl stop greinheritance.service failed :  rc = %d\n", WEXITSTATUS(rc));
                            }
                            if (g_pMeshAgent->dscpInheritRfcEnable && g_pMeshAgent->IsPodConnect)
                            {
                                rc= v_secure_system("systemctl start greinheritance.service");
                                if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
                                    MeshError("Failed systemctl start greinheritance.service  rc = %d\n",WEXITSTATUS(rc));
                                MeshInfo("Insert kernel module xmeshgre.ko \n");
                            }
                            g_pMeshAgent->IsdscpConfigEnabled = true;
                        }
                        else
                        {
                            if ( mac_index == 0 && g_pMeshAgent->IsdscpConfigEnabled && g_pMeshAgent->IsPodConnect)
                            {
                                g_pMeshAgent->IsdscpConfigEnabled = false;
                                if (g_pMeshAgent->dscpInheritRfcEnable)
                                {
                                    MeshInfo("xmeshgre.ko is running so deleting when dscp is cleared\n");
                                    rc= v_secure_system("systemctl stop greinheritance.service");
                                    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
                                        MeshError("systemctl stop greinheritance.service failed :  rc = %d\n", WEXITSTATUS(rc));
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                MeshWarning("undefined event %s \n",name);
            }
          }
        }
    }
    return NULL;
    // MeshInfo("Exiting from %s\n",__FUNCTION__);
}

/**
 * @brief Mesh Agent initialize client connection list
 *
 * Initialize the client list table with the devices connected before mesh was started.
 */

static void Mesh_InitEthHost_Sync(void)
{
    v_secure_system("dmcli eRT setv Device.Ethernet.X_RDKCENTRAL-COM_EthHost_Sync bool true");
    MeshError("EthHost_Sync rfc for connected client polling");
}

/**
 *  @brief Mesh Agent Initialize code
 *
 *  This function will initialize the Mesh Agent and set up any data required.
 *
 *  @return 0
 */
static int Mesh_Init(ANSC_HANDLE hThisObject)
{
    int status = 0;
#if defined(WAN_FAILOVER_SUPPORTED) || defined(ONEWIFI) || defined(GATEWAY_FAILOVER_SUPPORTED)
#ifndef DBUS_SUPPORT
    pthread_t tid_sub;
#endif
#endif
    int thread_status = 0;
    char thread_name[THREAD_NAME_LEN] = { 0 };
    errno_t rc = -1;
    // MeshInfo("Entering into %s\n",__FUNCTION__);
    oneWifiEnabled = (0 == access( ONEWIFI_ENABLED, F_OK ))? true:false;
    MeshInfo("oneWifi is %s \n", oneWifiEnabled? "enabled" : "disabled");

    wanFailOverEnabled = (access(WFO_ENABLED, F_OK) == 0 )? true:false;
    MeshInfo("wanFailOver is %s \n", wanFailOverEnabled? "enabled" : "disabled");
    // Create our message server thread
    thread_status = pthread_create(&mq_server_tid, NULL, msgQServer, NULL);
    if (thread_status == 0)
    {
        MeshInfo("msgQServer thread created successfully\n");

        rc = strcpy_s(thread_name, sizeof(thread_name),  "Mesh_msgQServer");
        if(rc != EOK)
        {
           ERR_CHK(rc);
           MeshError("Error in setting Mesh_msgQServer thread_name\n");
        }

        if ((rc == EOK) && (pthread_setname_np(mq_server_tid, thread_name) == 0))
        {
            MeshInfo("msgQServer thread name %s set successfully\n", thread_name);
        }
        else
        {
            MeshError("%s error occurred while setting msgQServer thread name\n", strerror(errno));
        }
    }
    else
    {
        MeshError("%s error occurred while creating msgQServer thread\n", strerror(errno));
        status = -1;
    }


    if (Mesh_Register_sysevent(hThisObject) == false)
    {
        MeshError("Mesh_Register_sysevent failed\n");
        status = -1;
    }
    else
    {
        MeshInfo("Mesh_Register_sysevent Successful\n");

        thread_status = pthread_create(&sysevent_tid, NULL, Mesh_sysevent_handler, NULL);
        if (thread_status == 0)
        {
            MeshInfo("Mesh_sysevent_handler thread created successfully\n");

            rc = strcpy_s(thread_name, sizeof(thread_name), "Mesh_sysevent");
            if(rc != EOK)
            {
                ERR_CHK(rc);
                MeshError("Error in setting Mesh_sysevent thread_name\n");
                return -1;
            }

            if (pthread_setname_np(sysevent_tid, thread_name) == 0)
            {
               MeshInfo("Mesh_sysevent_handler thread name %s set successfully\n", thread_name);
            }
            else
            {
                MeshError("%s error occurred while setting Mesh_sysevent_handler thread name\n", strerror(errno));
            }

            sleep(5);
        }
        else
        {
            MeshError("%s error occurred while creating Mesh_sysevent_handler thread\n", strerror(errno));
            status = -1;
        }
    }
    // Start a server for dnsmasq lease notification
    thread_status = 0;
    thread_status = pthread_create(&lease_server_tid, NULL, leaseServer, NULL);
    if (thread_status == 0)
    {
        MeshInfo("leaseServer thread created successfully\n");

        //memset( thread_name, '\0', sizeof(char) * THREAD_NAME_LEN );
        /* Coverity Issue Fix - CID:59861 DC.STRING_BUFFER  */
        rc = strcpy_s(thread_name, sizeof(thread_name), "MeshLeaseServer");
        if(rc != EOK)
        {
            ERR_CHK(rc);
            MeshError("Error in setting MeshLeaseServer thread_name\n");
            return -1;
        }

        if (pthread_setname_np(lease_server_tid, thread_name) == 0)
        {
            MeshInfo("leaseServer thread name %s set successfully\n", thread_name);
        }
        else
        {
            MeshError("%s error occurred while setting msgQServer thread name\n", strerror(errno));
        }
    }
    else
    {
        MeshError("%s error occurred while creating msgQServer thread\n", strerror(errno));
        status = -1;
    } 
    // Start message queue client thread (Communications to/from RDKB CcspWifiSsp)

    parodusInit();
#ifndef DBUS_SUPPORT
    meshRbusInit();
#endif
#if defined  ONEWIFI && !defined DBUS_SUPPORT
    get_sta_active_interface_name();
#endif
#if !defined DBUS_SUPPORT && !defined  RDKB_EXTENDER_ENABLED && defined(GATEWAY_FAILOVER_SUPPORTED)
    rbus_get_gw_present();
#endif

#if !defined(RDKB_EXTENDER_ENABLED) && defined(GATEWAY_FAILOVER_SUPPORTED) && defined(_RDKB_GLOBAL_PRODUCT_REQ_)
    rbusValue_t value;
    if( RBUS_ERROR_SUCCESS == rbus_get(handle,TR181_GLOBAL_FEATURE_PARAM_GFO_SUPPORTED, &value) ) 
    {
        unsigned int data;
        data = rbusValue_GetBoolean(value);
        meshRbusEvent[MESH_RBUS_GATEWAY_PRESENT].feature_supported = data?1:0;
        MeshInfo("rbus_get for %s: value:%s\n",TR181_GLOBAL_FEATURE_PARAM_GFO_SUPPORTED, (data?"SUPPORTED":"NOT_SUPPORTED"));
    }
#endif /** !(RDKB_EXTENDER_ENABLED) && (GATEWAY_FAILOVER_SUPPORTED) && (_RDKB_GLOBAL_PRODUCT_REQ_) */

#if defined(WAN_FAILOVER_SUPPORTED) || defined(ONEWIFI) || defined(GATEWAY_FAILOVER_SUPPORTED)
#if !defined DBUS_SUPPORT    
    thread_status = 0;
    thread_status = pthread_create(&tid_sub, NULL, handle_rbus_Subscribe,NULL);
    if (thread_status == 0)
    {
        MeshInfo("rbus_Subscribe thread created successfully\n");
	rc = strcpy_s(thread_name, sizeof(thread_name), "rbus_Subscribe");
	if(rc != EOK)
	{
	    ERR_CHK(rc);
            MeshError("Error in setting rbus_Subscribe thread_name\n");
            return -1;
        }
	if (pthread_setname_np(tid_sub, thread_name) == 0)
        {
            MeshInfo("rbus_Subscribe thread name %s set successfully\n", thread_name);
        }
        else
        {
            MeshError("%s error occurred while setting rbus_Subscribe thread name\n", strerror(errno));
        }
    }
    else
    {
        MeshError("%s error occurred while creating rbus_Subscribe thread\n", strerror(errno));
        status = -1;
    }
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
    device_mode = Mesh_SysCfgGetInt("Device_Mode");
    if (device_mode == GATEWAY_MODE)
    {
        snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", MESH_BHAUL_BRIDGE);
#ifndef DBUS_SUPPORT
        publishRBUSEvent(MESH_RBUS_PUBLISH_BACKHAUL_IFNAME, (void *)mesh_backhaul_ifname,handle);
#endif
    }
    else
        snprintf(mesh_backhaul_ifname, MAX_IFNAME_LEN, "%s", MESH_XLE_BRIDGE);

    MeshInfo("Current device mode = %d\n",device_mode);
#endif
#endif
#ifndef DBUS_SUPPORT
    subscribeSpeedTestStatus();
#endif
#ifdef MESH_OVSAGENT_ENABLE
    if (!ovs_agent_api_init(OVS_MESH_AGENT_COMPONENT_ID))
    {
        MeshError("%s: Failed to init the OvsAgentApi\n", __FUNCTION__);
        status = -1;
    }
#else
    MeshInfo("%s: OvsAgentApi is not integrated in this platform yet\n", __FUNCTION__);
#endif

    if (!channel_keepout_init()) {
        MeshError("channel_keepout_init failed..\n");
    }

    if (!hd_recommendation_init()) {
        MeshError("%s hd_recommendation_init failed..\n",__func__);
    }

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return status;
}

/**
 *  @brief Mesh Agent Deinitialize code
 *
 *  This function will deinitialize the Mesh Agent and destroy any resources setup previously.
 *
 *  @return 0
 */
static int Mesh_Deinit(ANSC_HANDLE hThisObject)
{
    int status = 0;

    PCOSA_DATAMODEL_MESHAGENT pMyObject = (PCOSA_DATAMODEL_MESHAGENT) hThisObject;
    if (!pMyObject)
    {
        MeshWarning("%s Datamodel object is NULL\n",__FUNCTION__);
    }

#ifdef MESH_OVSAGENT_ENABLE
    if (!ovs_agent_api_deinit())
    {
        MeshError("%s: Failed to deinit the OvsAgentApi\n", __FUNCTION__);
        status = -1;
    }
#else
    MeshInfo("%s: OvsAgentApi is not integrated in this platform yet\n", __FUNCTION__);
#endif

    // MeshInfo("Exiting from %s\n",__FUNCTION__);
    return status;
}

ANSC_STATUS
CosaDmlMeshAgentInit
    (
        ANSC_HANDLE                 hThisObject
    )
{
    int res;
    MeshInfo("Initialize MeshAgent\n");

    // Ensure meshwifi service not started before init done
    pthread_mutex_lock(&mesh_handler_mutex);
    res = Mesh_Init(hThisObject);
    pthread_mutex_unlock(&mesh_handler_mutex);
    if (res != 0)
    {
        MeshError("Mesh Agent Initialization failed\n");
        return ANSC_STATUS_FAILURE;
    }
    MeshInfo("MeshAgent initialized\n");
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlMeshAgentDeinit
    (
        ANSC_HANDLE                 hThisObject
    )
{
    int res;
    MeshInfo("Deinitialize MeshAgent\n");

    // Ensure meshwifi service not started before deinit done
    pthread_mutex_lock(&mesh_handler_mutex);
    res = Mesh_Deinit(hThisObject);
    pthread_mutex_unlock(&mesh_handler_mutex);
    if (res != 0)
    {
        MeshError("Mesh Agent Deinitialization failed\n");
        return ANSC_STATUS_FAILURE;
    }
    MeshInfo("MeshAgent Deinitialized\n");
    return ANSC_STATUS_SUCCESS;
}

#endif
