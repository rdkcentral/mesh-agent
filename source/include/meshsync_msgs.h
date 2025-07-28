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
 * meshcfg.h
 *
 */

#ifndef MESHCFG_H_
#define MESHCFG_H_

#include <sys/types.h>
#include <inttypes.h>

#define MAX_BSS_ID_STR       18
#define MAX_SSID_LEN         65
#define MAX_PASS_LEN         65
#define MAX_MODE_LEN         25
#define MAX_SUBNET_LEN       25
#define MAX_IP_LEN           64
#define MESH_MAX_URL_LEN     256
#define MAX_TXRATE_LEN       256
#define MAX_CHANNEL_MODE_LEN 32
#define MAX_MAC_ADDR_LEN     18
#define MAX_HOSTNAME_LEN     256
#define MAX_RFC_PARAM_NAME   256
#define ETHBHAUL_BR_IP       "169.254.85.1"
#define MESHBHAUL_BR         "br403"
#define XHS_VLAN             101
#define LNF_VLAN             106
#define PRIV_VLAN            100
#define MAX_VLANS            3
#define XHS_BR               "brlan1"
#define LNF_BR               "br106"
#define PRIV_BR              "brlan0"
#define LNF_BR_XF3           "brlan6"

#ifdef WAN_FAILOVER_SUPPORTED
#define ETH_IFNAME_MAX_LEN   128
#define MESH_EXTENDER_VLAN   200
#define MESH_ETHPORT        "eth"
#endif
#define MAX_IFNAME_LEN       64
#define MAX_IF               3
#define MAX_IPV4_LENGTH      16

#if defined(ENABLE_MESH_SOCKETS)
/**************************************************************************/
/*      Unix Domain Socket Name                                           */
/**************************************************************************/
#define MESH_SOCKET_PATH_NAME   "\0/tmp/mesh-socket-queue" // MeshAgent Server message socket
#else
/**************************************************************************/
/*      Posix Message Queue Names                                         */
/**************************************************************************/
#define MESH_SERVER_QUEUE_NAME   "/mqueue-mesh-server" // Message traffic from Mesh Application Layer to RDKB
#define MESH_CLIENT_QUEUE_NAME   "/mqueue-mesh-client" // Message traffic from RDKB to Mesh Application Layer
#endif

#define MAX_FINGERPRINT_LEN 512
#define MAX_POD_COUNT 	    16

/**************************************************************************/
/*      Mesh sync message types                                         */
/**************************************************************************/

typedef enum {
    MESH_WIFI_RESET,
    MESH_WIFI_RADIO_CHANNEL,
    MESH_WIFI_RADIO_CHANNEL_MODE,
    MESH_WIFI_SSID_NAME,
    MESH_WIFI_SSID_ADVERTISE,
    MESH_WIFI_AP_SECURITY,
    MESH_WIFI_AP_KICK_ASSOC_DEVICE,
    MESH_WIFI_AP_KICK_ALL_ASSOC_DEVICES,
    MESH_WIFI_AP_ADD_ACL_DEVICE,
    MESH_WIFI_AP_DEL_ACL_DEVICE,
    MESH_WIFI_MAC_ADDR_CONTROL_MODE,
    MESH_SUBNET_CHANGE,
    MESH_URL_CHANGE,
    MESH_WIFI_STATUS,
    MESH_WIFI_ENABLE,
    MESH_STATE_CHANGE,
    MESH_WIFI_TXRATE,
    MESH_CLIENT_CONNECT,
    MESH_DHCP_RESYNC_LEASES,
    MESH_DHCP_ADD_LEASE,
    MESH_DHCP_REMOVE_LEASE,
    MESH_DHCP_UPDATE_LEASE,
    MESH_WIFI_RADIO_CHANNEL_BW,
    MESH_ETHERNET_MAC_LIST,
    MESH_RFC_UPDATE,
    MESH_TUNNEL_SET,
    MESH_TUNNEL_SET_VLAN,
    MESH_REDUCED_RETRY,
    MESH_WIFI_SSID_CHANGED,
    MESH_WIFI_RADIO_OPERATING_STD,
    MESH_SYNC_SM_PAUSE,
    MESH_WIFI_OFF_CHAN_ENABLE,
    MESH_GATEWAY_ENABLE,
    MESH_WIFI_OPT_MODE,
    MESH_WIFI_OPT_BROKER,
    MESH_WIFI_REINIT_PERIOD,
    MESH_OPT_ENABLE_MODE_BROKER_URL,
    MESH_OPT_ENABLE_MODE_BROKER_PORT,
    MESH_OPT_ENABLE_MODE_BROKER_TOPIC,
    MESH_WIFI_MOTION,
    MESH_CA_CERT,
#if defined(ONEWIFI)
    MESH_SYNC_STATUS,
    MESH_CONTROLLER_STATUS,
    MESH_WIFI_EXTENDER_MODE,
    MESH_ADD_DNSMASQ,
    MESH_XLE_MODE_CLOUD_CTRL_RFC,
#endif
#ifdef WAN_FAILOVER_SUPPORTED
    MESH_BACKUP_NETWORK,
    MESH_WFO_ENABLED,
#endif
#ifdef ONEWIFI
    MESH_GET_STAINFO,
    MESH_BRHOME_IP,
    MESH_TRIGGER_DISASSOC,
#endif
    MESH_EBH_STATUS,
    MESH_EBH_INFO,
    MESH_WIFI_DYNAMIC_PROFILE,
    MESH_FIREWALL_START,
    MESH_DSCP_INHERIT_ENABLE,
    MESH_RECORDER_ENABLE,
    MESH_SYNC_MSG_TOTAL
} eMeshSyncType;

// MeshSync Message structure.      
typedef struct                      
{       
    eMeshSyncType mType;       // Enum value of the mesh sync msg
    char         *msgStr;      // mesh sync message string
    char         *sysStr; // sysevent string
} MeshSync_MsgItem;

// RFC parameter type
typedef enum {
    rfc_string = 0,
    rfc_int,
    rfc_unsignedInt,
    rfc_boolean,
    rfc_dateTime,
    rfc_base64,
    rfc_long,
    rfc_unsignedLong,
    rfc_float,
    rfc_double,
    rfc_byte,
    rfc_none,
} eRfcType;

/**
 * Mesh States
 */
typedef enum {
    MESH_STATE_FULL = 0,
    MESH_STATE_MONITOR,
    MESH_STATE_WIFI_RESET,
    MESH_STATE_TOTAL
} eMeshStateType;

/**
 * Mesh WifiOptimization Mode
 */
typedef enum {
    MESH_MODE_DISABLE = 0,
    MESH_MODE_MONITOR,
    MESH_MODE_ENABLE,
    MESH_MODE_TOTAL
} eWifiOptimizationMode;

/**
 * Mesh Status states
 */
typedef enum {
    MESH_WIFI_STATUS_OFF = 0,
    MESH_WIFI_STATUS_INIT,
    MESH_WIFI_STATUS_MONITOR,
    MESH_WIFI_STATUS_FULL,
    MESH_WIFI_STATUS_TOTAL
} eMeshWifiStatusType;

#ifdef WAN_FAILOVER_SUPPORTED
/**
 * Mesh Device Mode 
 */
typedef enum {
    MESH_EXTENDER_DEVICE_MODE = 0,
    MESH_GATEWAY_DEVICE_MODE
} eMeshDeviceMode;
#endif

/**
 * Mesh Connected Client Interfaces
 */
typedef enum {
    MESH_IFACE_NONE = 0,
    MESH_IFACE_ETHERNET,
    MESH_IFACE_MOCA,
    MESH_IFACE_WIFI,
    MESH_IFACE_OTHER,
    MESH_IFACE_TOTAL
} eMeshIfaceType;

/**
 * Mesh Sync Wifi Reset/Init message
 */
typedef struct _MeshWifiReset {
    uint8_t reset; // boolean dummy value for structure set to true.
} MeshWifiReset;

/**
 * Mesh Sync Wifi SSID name change message
 */
typedef struct _MeshWifiSSIDName {
    uint32_t  index;                    // index [0-15]
    char      ssid[MAX_SSID_LEN];       // SSID
} MeshWifiSSIDName;

typedef struct _MeshWifiOffChannelScanEnable {
    uint8_t   enable;       //off chan scan bool val
} MeshWifiOffChannelScanEnable;

typedef struct _MeshWifiSSIDChanged {
    uint32_t  index;                    // index [0-15]
    uint8_t   enable;       // SSID
    char      ssid[MAX_SSID_LEN];
} MeshWifiSSIDChanged;

typedef struct _MeshWifiXLEExtenderMode {
    char    InterfaceName[MAX_SSID_LEN];
    char    bssid[MAX_BSS_ID_STR];
    uint8_t status;
    uint8_t isStatusSet;
    int device_mode;
} MeshWifiXLEExtenderMode;

/**
 * Mesh Sync Wifi SSID Advertise change message
 */
typedef struct _MeshWifiSSIDAdvertise {
    uint32_t  index;                    // index [0-15]
    uint8_t   enable;                   // boolean enable
} MeshWifiSSIDAdvertise;

/**
 * Mesh Sync Wifi Radio channel change
 */
typedef struct _MeshWifiRadioChannel {
    uint32_t index;                // Radio index
    uint32_t channel;              // Channel
} MeshWifiRadioChannel;

/**
 * Mesh Sync Wifi Radio channel mode change
 */
typedef struct _MeshWifiRadioChannelMode {
    uint32_t index;                             // Radio index
    char     channelMode[MAX_CHANNEL_MODE_LEN]; // ChannelMode
    uint8_t  gOnlyFlag;            // Is this g only?
    uint8_t  nOnlyFlag;            // Is this n only?
    uint8_t  acOnlyFlag;           // Is this ac only?
} MeshWifiRadioChannelMode;

/**
 * Mesh Sync Wifi Radio Operating Standard change
 */
typedef struct _MeshWifiRadioOperatingStd {
    uint32_t index;                             // Radio index
    char     channelMode[MAX_CHANNEL_MODE_LEN]; // ChannelMode
} MeshWifiRadioOperatingStd;

/**
 * Mesh Sync Wifi configuration change message
 */
typedef struct _MeshWifiAPSecurity {
    uint32_t  index;                    // AP index [0-15]
    char      passphrase[MAX_PASS_LEN]; // AP Passphrase
    char      secMode[MAX_MODE_LEN];    // Security mode
    char      encryptMode[MAX_MODE_LEN];    // Encryption mode
} MeshWifiAPSecurity;


/**
 * Mesh Sync Wifi Kick AP Associated Device based on device mac
 */
typedef struct _MeshWifiAPKickAssocDevice {
    uint32_t  index;                    // AP index [0-15]
    char      mac[MAX_MAC_ADDR_LEN];    // Mac Address
} MeshWifiAPKickAssocDevice;

/**
 * Mesh Sync Wifi Kick All AP Associated Devices
 */
typedef struct _MeshWifiAPKickAllAssocDevices {
    uint32_t  index;                    // AP index [0-15]
} MeshWifiAPKickAllAssocDevices;


/**
 * Mesh Sync Wifi AP Add Acl Device
 */
typedef struct _MeshWifiAPAddAclDevice {
    uint32_t  index;                    // AP index [0-15]
    char      mac[MAX_MAC_ADDR_LEN];    // Mac Address
} MeshWifiAPAddAclDevice;


/**
 * Mesh Sync Wifi AP Delete Acl Device
 */
typedef struct _MeshWifiAPDelAclDevice {
    uint32_t  index;                    // AP index [0-15]
    char      mac[MAX_MAC_ADDR_LEN];    // Mac Address
} MeshWifiAPDelAclDevice;

/**
 * Mesh Sync Wifi Mac Address Control Mode
 */
typedef struct _MeshWifiMacAddrControlMode {
    uint32_t  index;                        // AP index [0-15]
    uint8_t   isEnabled;   // Filter Enabled bool
    uint8_t   isBlacklist; // blacklist=1; whitelist=0
} MeshWifiMacAddrControlMode;


/**
 * Mesh Sync Subnet configuration change message
 */
typedef struct _MeshSubnetChange {
    char gwIP[MAX_IP_LEN];   // GW IP value
    char netmask[MAX_SUBNET_LEN];   // Subnet value
} MeshSubnetChange;

/**
 * Mesh Sync URL configuration change message
 */
typedef struct _MeshUrlChange {
    char url[MESH_MAX_URL_LEN];  // url
} MeshUrlChange;

/**
 * Mesh Sync msg for ethernet mac filter of pod
 */
typedef struct _MeshEthernetMac {
    char mac[MAX_MAC_ADDR_LEN];  // mac
} MeshEthMac;

/**
 * Mesh Network Status message
 */
typedef struct _MeshWifiStatus {
    eMeshWifiStatusType status; // Status of mesh network
} MeshWifiStatus;

/**
 * Mesh Gateway mode set by cloud
 */
typedef struct _MeshGatewayEnable {
    uint8_t enable;
}MeshGatewayEnable;

/**
 * Mesh wifi optimization mode
 */
typedef struct _MeshWifiOptimizationMode {
    eWifiOptimizationMode mode;
}MeshWifiOptimizationMode;

typedef struct _MeshWifiOptMqttBroker {
    char ip [MAX_IPV4_LENGTH];
    int port;
}MeshWifiOptMqttBroker;

typedef struct _MeshCaInfo {
    uint8_t is_comodo_enabled;
} MeshCaInfo;

#ifdef WAN_FAILOVER_SUPPORTED
/**
 * Mesh Network Type message
 */
typedef struct _MeshNetworkType {
    eMeshDeviceMode type; // Status of mesh network
    char ifname [MAX_IFNAME_LEN];
    uint8_t   status;
} MeshNetworkType;

typedef struct _MeshWFOEnabledStatus {
    uint8_t isWFOEnabledSet;
    uint8_t WFOEnabledStatus;
} MeshWFOEnabledStatus;
#endif

#ifdef ONEWIFI
typedef struct _MeshGetSTAInfo {
    uint8_t status;
} MeshGetSTAInfo;
#endif

/**
 * Mesh State message
 */
typedef struct _MeshStateChange {
    eMeshStateType state; // State of mesh network
} MeshStateChange;

/**
 * Mesh WiFi TxRate
 */
typedef struct _MeshWifiTxRate {
    uint32_t  index;                        // AP index [0-15]
    char      basicRates[MAX_TXRATE_LEN];   // Basic Rates
    char      opRates   [MAX_TXRATE_LEN];   // Operational Rates
} MeshWifiTxRate;

/**
 * Mesh Client Connect
 */
typedef struct _MeshClientConnect {
    eMeshIfaceType  iface;                  // Interface
    char            mac[MAX_MAC_ADDR_LEN];  // MAC address
    char            host[MAX_HOSTNAME_LEN];  // Hostname
    uint8_t         isConnected;            // true=connected; false=offline/disconnected
} MeshClientConnect;

/**
 * DHCP lease notification
 */
typedef struct _MeshWifiDhcpLease {
    char        mac[MAX_MAC_ADDR_LEN];
    char        ipaddr[MAX_IP_LEN];
    char        hostname[MAX_HOSTNAME_LEN];
    char        fingerprint[MAX_FINGERPRINT_LEN];
} MeshWifiDhcpLease;

/**
* Message from dnsmasq to create
* tunnels for ethernet pods
*/
typedef struct _PodTunnel {
    char        podmac[MAX_MAC_ADDR_LEN];
    char        podaddr[MAX_IP_LEN];
    char        dev[16];
} PodTunnel;

/**
 * RFC update message structure - to be sent to plume
 */
typedef struct _MeshRFCUpdate {
    char        paramname[MAX_RFC_PARAM_NAME];
    char        paramval[MAX_RFC_PARAM_NAME];
    eRfcType    type;
} MeshRFCUpdate;

typedef struct _MeshReducedRetry {
    uint8_t         isenabled;
} MeshReducedRetry;

typedef struct _MeshWifiMotion {
    uint8_t         isenabled;
} MeshWifiMotion;

typedef struct _MeshEbhStatus {
    uint8_t     enabled;
} MeshEbhStatus;

typedef struct _MeshTunnelSet {
    char        ifname[64];
    char        localIp[MAX_IP_LEN];
    char        remoteIp[MAX_IP_LEN];
    char        dev[64];
    char        bridge[64];
} MeshTunnelSet;

typedef struct _MeshTunnelSetVlan {
    char        ifname[64];
    char        parent_ifname[64];
    char        bridge[64];
    int         vlan;
} MeshTunnelSetVlan;
/**
 * Channel Bandwidth change notification
 */
typedef struct _MeshWifiRadioChannelBw {
    int index;
    int bw;
} MeshWifiRadioChannelBw;

/**
 * Speedtest Event Notification
 */
typedef struct _MeshSyncSMPause {
    int status;
    int timeout;
} MeshSyncSMPause;

#ifdef ONEWIFI
/**
 * br-home IP assigned notification
 */
typedef struct _MeshBrhomeIp {
    char ip[16];
} MeshBrhomeIp;

typedef struct _MeshSta_dnsmasq_info
{
    char ifname[MAX_IFNAME_LEN];
    char dhcp_start[MAX_IP_LEN];
    char dhcp_end[MAX_IP_LEN];
    int lease_time;
}MeshSta_dnsmasq_info;

typedef enum {
    MESH_CONTROLLER_CONNECTED = 0,
    MESH_CONTROLLER_CONNECTING,
    MESH_CONTROLLER_FAILURE,
    MESH_STA_DISCONNECTED,
    MESH_STA_CONNECTED,
    MESH_MQTT_RECVD,
    MESH_CONTROLLER_CONNECTED_VIA_WBH,
    MESH_CONTROLLER_CONNECTED_VIA_EBH,
    MESH_TOTAL_STATUS
}eMeshSyncStatus;

typedef struct _MeshSync_status {
    eMeshSyncStatus status;
} MeshSync_status;

typedef struct _MeshTriggerDisassociation
{
    uint8_t status;
}MeshTriggerDisassociation;
#endif

typedef struct {
    uint8_t profile_id;
} MeshWifiDynamicProfile;

/**
 * Mesh Sync message
 */
typedef struct _MeshSync {
    eMeshSyncType msgType;

    union {
        MeshWifiReset                   wifiReset;
        MeshWifiRadioChannel            wifiRadioChannel;
        MeshWifiRadioChannelMode        wifiRadioChannelMode;
        MeshWifiRadioOperatingStd       wifiRadioOperatingStd;
        MeshWifiSSIDName                wifiSSIDName;
        MeshWifiSSIDChanged             wifiSSIDChanged;
        MeshWifiXLEExtenderMode         onewifiXLEExtenderMode;
        MeshWifiSSIDAdvertise           wifiSSIDAdvertise;
        MeshWifiAPSecurity              wifiAPSecurity;
        MeshWifiAPKickAssocDevice       wifiAPKickAssocDevice;
        MeshWifiAPKickAllAssocDevices   wifiAPKickAllAssocDevices;
        MeshWifiAPAddAclDevice          wifiAPAddAclDevice;
        MeshWifiAPDelAclDevice          wifiAPDelAclDevice;
        MeshWifiMacAddrControlMode      wifiMacAddrControlMode;
        MeshSubnetChange                subnet;
        MeshUrlChange                   url;
        MeshWifiStatus                  wifiStatus;
        MeshStateChange                 meshState;
        MeshWifiTxRate                  wifiTxRate;
        MeshClientConnect               meshConnect;
        MeshWifiDhcpLease               meshLease;
        MeshWifiRadioChannelBw          wifiRadioChannelBw; 
        MeshEthMac			ethMac;
        MeshRFCUpdate			rfcUpdate; 
        MeshTunnelSet			tunnelSet; 
        MeshTunnelSetVlan		tunnelSetVlan;
        MeshReducedRetry                retryFlag;
        MeshSyncSMPause                 speedtestCfg;
        MeshGatewayEnable               gateway;
        MeshWifiOptimizationMode        meshwifiOpt;
        MeshWifiOptMqttBroker           meshwifiOptMqttBroker;
        MeshWifiMotion                  meshwifiMotion;
        MeshCaInfo                      comodoCa;
#ifdef WAN_FAILOVER_SUPPORTED
        MeshNetworkType                 networkType;
        MeshWFOEnabledStatus            meshWFOEnabled;
#endif
#ifdef ONEWIFI
        MeshGetSTAInfo                  staInfo;
        MeshBrhomeIp                    brhomeIP;
        MeshSta_dnsmasq_info            STADnsMasqInfo;
        MeshSync_status                 syncStatus;
        MeshTriggerDisassociation       triggerStatus;
#endif
        MeshWifiOffChannelScanEnable    wifiOffChannelScanEnable;
        MeshEbhStatus                   ebhStatus;
        MeshWifiDynamicProfile          wifiDynamicProfile;
    } data;
} MeshSync;

typedef struct _EthPodMsg {
    char        pod_mac[MAX_MAC_ADDR_LEN];
} EthPodMsg;

typedef struct _MeshNotify {
   union {
    MeshWifiDhcpLease        lease;
    PodTunnel                tunnel; 
    EthPodMsg                eth_msg;
   };
   int msgType;
} MeshNotify;

//Ethernet bhaul notify msg to dnsmasq
typedef enum {
    STOP_POD_FILTER = 0,
    START_POD_FILTER
} ePodMacNotifyType;
    
typedef struct _PodMacNotify {
    char        mac[MAX_MAC_ADDR_LEN];
    ePodMacNotifyType msgType;
} PodMacNotify;

#endif /* MESHCFG_H_ */
