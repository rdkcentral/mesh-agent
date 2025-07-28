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

#ifndef  _COSA_WEBCONFIG_API_H
#define  _COSA_WEBCONFIG_API_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <webconfig_framework.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

#define SUBDOC_COUNT 8

#define MESH_CACHE_SIZE 4
#define BLOCK_SIZE 32
#define VAL_BLOCK_SIZE 129 // for ipv6 address 128 + 1 size is needed
#define MESH_DEFAULT_TIMEOUT 120

#define MESH_ENABLE                  "mesh_enable"
#define ETHERNET_BACKHAUL_ENABLE     "ethbhaul_enable"

#ifdef WEBCFG_TEST_SIM

#define NACK_SIMULATE_FILE "/tmp/sim_nack"
#define TIMEOUT_SIMULATE_FILE "/tmp/sim_timeout"

#endif

#define match(p, s) ((((strncmp((p)->key.via.str.ptr, s, (p)->key.via.str.size))== 0)&&((sizeof(s)-1) == (p)->key.via.str.size))?0:1)

#define member_size(type, member) sizeof(((type *)0)->member)
// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

// Same as ARRAY_SIZE, except returned signed value
#ifndef ARRAY_LEN
#define ARRAY_LEN(x)  ((int)ARRAY_SIZE(x))
#endif /* ARRAY_LEN */

#ifndef ARRAY_AND_SIZE
#define ARRAY_AND_SIZE(x)   (x),ARRAY_SIZE(x)
#endif /* ARRAY_AND_SIZE */
#define C_ITEM_STR(key, str)        {0, sizeof(str)-1, (int)key, (intptr_t)str}
#define c_get_str_by_key(list, key)         _c_get_str_by_key(ARRAY_AND_SIZE(list), key)
#define c_get_item_by_str(list, str)        _c_get_item_by_str(ARRAY_AND_SIZE(list), str)

enum {
    HELPERS_OK = 0,
    HELPERS_OUT_OF_MEMORY,
    HELPERS_INVALID_FIRST_ELEMENT,
    HELPERS_MISSING_WRAPPER
};

enum {
    MB_OK                       = HELPERS_OK,
    MB_OUT_OF_MEMORY            = HELPERS_OUT_OF_MEMORY,
    MB_INVALID_FIRST_ELEMENT    = HELPERS_INVALID_FIRST_ELEMENT,
    MB_MISSING_PM_ENTRY         = HELPERS_MISSING_WRAPPER,
    MB_INVALID_OBJECT,
    MB_INVALID_VERSION,
};

typedef enum {
    SP_CLIENT_KICK_NONE             = 0,
    SP_CLIENT_KICK_DISASSOC,
    SP_CLIENT_KICK_DEAUTH,
    SP_CLIENT_KICK_BSS_TM_REQ,
    SP_CLIENT_KICK_RRM_BR_REQ,
    SP_CLIENT_KICK_BTM_DISASSOC,
    SP_CLIENT_KICK_BTM_DEAUTH,
    SP_CLIENT_KICK_RRM_DISASSOC,
    SP_CLIENT_KICK_RRM_DEAUTH
} sp_client_kick_t;

typedef enum {
    SP_CLIENT_PREF_ALLOWED_NEVER              = 0,
    SP_CLIENT_PREF_ALLOWED_HWM,
    SP_CLIENT_PREF_ALLOWED_ALWAYS,
    SP_CLIENT_PREF_ALLOWED_NON_DFS
} sp_client_pref_allowed;

typedef enum {
    SP_CLIENT_REJECT_NONE           = 0,
    SP_CLIENT_REJECT_PROBE_ALL,
    SP_CLIENT_REJECT_PROBE_NULL,
    SP_CLIENT_REJECT_PROBE_DIRECT,
    SP_CLIENT_REJECT_AUTH_BLOCKED
} sp_client_reject_t;

typedef enum {
    MESH = 0,
    STEERING_PROFILE_DEFAULT,
    DEVICE,
    WIFI_CONFIG,
    CONFIGS,
    INTERFERENCE,
    WIFI_MOTION,
    CHANNEL_PLAN_DATA
}eBlobType;

typedef enum {
    TYPE_STRING,
    TYPE_BOOLEAN,
    TYPE_INT
} eValueType;

typedef enum
{
    RADIO_TYPE_NONE = 0,
    RADIO_TYPE_2G,
    RADIO_TYPE_5G,
    RADIO_TYPE_5GL,
    RADIO_TYPE_5GU,
    RADIO_TYPE_6G
} radio_type_t;

typedef struct {
    int32_t         value;
    int32_t         param;
    intptr_t        key;
    intptr_t        data;
} c_item_t;

typedef struct {
  sp_client_pref_allowed    pref_6g;
  uint8_t                   hwm;
} sp_gw_only_6g_t;

typedef struct {
  sp_client_pref_allowed    pref_5g;
  uint8_t                   lwm;
  sp_gw_only_6g_t           *gw_only_6g;
} sp_gw_only_t;

typedef struct {
  uint8_t                 valid_interval_tbtt; //valid_interval
  uint8_t                 abridged; //abridged
  uint8_t                 pref; //pref
  uint8_t                 disassociation_imminent; //disassoc_imminent
  uint16_t                bss_termination; //bss_term
  int                     retry_count; //btm_max_retries
  int                     retry_interval; //btm_retry_interval
  bool                    include_neighbors;//inc_neigh
} sp_btm_params_t;

typedef struct {
  uint8_t                   hwm2;
  uint8_t                   hwm3;
  uint8_t                   lwm2;
  uint8_t                   lwm3;
  bool                      steerDuringBackoff;
}sp_band_steering_6g_t;

typedef struct {
  bool                      enable; //Not in ovsdb
  int                       backoff_second; //backoff_secs
  bool                      steer_during_backoff; //steer_during_backoff
  int                       backoff_exp_base; //backoff_exp_base
  int                       sticky_kick_guard_time;
  int                       sticky_kick_backoff_time;
  uint8_t                   hwm;
  uint8_t                   kick_reason;
  sp_client_kick_t          kick_type;
  uint8_t                   sticky_kick_reason;
  sp_client_kick_t          sticky_kick_type;
  sp_client_pref_allowed    pref_allowed;
  sp_client_pref_allowed    pref_6g;
  bool                      pre_assoc_auth_block;
  uint8_t                   lwm;
  uint8_t                   bottomLwm; //Not in ovsdb
  int                       max_rejects;
  sp_client_reject_t        reject_detection;
  int                       max_rejects_period; //rejects_tmout_secs
  bool                      kick_upon_idle;
  uint16_t                  kick_debounce_period;
  uint16_t                  sticky_kick_debounce_period;
  bool                      neighbor_list_filter_by_beacon_report; //Not in ovsdb
  bool                      neighborListFilterByBTMStatus; //Not in ovsdb
  int                       btmMaxNeighbors; //Not in ovsdb
  int                       btmMaxNeighbors6g; //Not in ovsdb
  sp_band_steering_6g_t     *band_steering_6g;
  sp_btm_params_t           *steering_btm_params;
  sp_btm_params_t           *sticky_btm_params;
  sp_gw_only_t              *for_gw_only;
}sp_band_steering_t;

typedef struct {
  bool                      enable;
  bool                      override_default_11kv;
  int                       backoff_seconds;
  int                       max_kicks_in_hour;
  unsigned int              busy_threshold_mbps;
  int                       max_poor_throughput_count;
  unsigned int              tp_change_mbps;
  int                       tp_improvement_pct;
  unsigned int              tp_change_mbps_2g_only;
  int                       tp_improvement_pct_2g_only;
  unsigned int              tp_change_mbps_downsteer;
  int                       tp_improvement_pct_downsteer;
  unsigned int              tp_change_mbps_5g_to_6g;
  int                       tp_improvement_pct_5g_to_6g;
  unsigned int              tp_change_mbps_6g_to_5g;
  int                       tp_improvement_pct_6g_to_5g;
  uint8_t                   kick_reason;
  sp_client_kick_t          kick_type;
  sp_client_kick_t          spec_kick_type;
  uint8_t                   lwm;
  uint8_t                   lwm_6g;
  uint8_t                   hwm;
  bool                      auth_block;
  bool                      probe_block;
  int                       auth_reject_reason;
  int                       max_rejects;
  sp_client_reject_t        reject_detection;
  int                       max_rejects_period;
  int                       recovery_period;
  int                       enforce_period;
  int                       sc_kick_debounce_period;
  sp_btm_params_t           *kv_params_direct;
}sp_client_steering_t;

typedef struct {
  bool is_supported;
}sp_dfs_t;

typedef struct {
  sp_band_steering_t        band_steer;
  //sp_band_steering_6g_t     6g_band_steer;
  //sp_client_steer_t         client_steer;
  //sp_dfs_t                  dfs_data;
}spsteeringdoc_t;

typedef struct {
    int lwm;
}DpGwOnlyOverlay;

typedef struct {
    sp_client_pref_allowed    pref_6g;
}DpGwOnlyOverlay6g;

typedef struct {
    bool present_enable;
    bool enable;
    bool present_kickType;
    sp_client_kick_t kickType;
    bool present_stickyKickType;
    sp_client_kick_t stickyKickType;
    bool present_hwm;
    int hwm;
    bool present_lwm;
    int lwm;
    bool present_kickUponIdleOnly;
    bool kickUponIdleOnly;
    bool present_gwOnly;
    DpGwOnlyOverlay *gwOnly;
    bool present_preAssociationAuthBlock;
    bool preAssociationAuthBlock;
}DpBandSteering_t;

typedef struct {
    bool present_enable;
    bool enable;
    bool present_overrideDefault11kv;
    bool overrideDefault11kv;
    bool present_retryTimeoutHours;
    int retryTimeoutHours;
    bool present_maxPoorThroughputCount;
    int maxPoorThroughputCount;
    bool present_kickType;
    sp_client_kick_t  kickType;
    bool present_specKickType;
    sp_client_kick_t specKickType;
    bool present_lwm2;
    int lwm2;
    bool present_lwm3;
    int lwm3;
    bool present_hwm2;
    int hwm2;
    bool present_hwm3;
    int hwm3;
    bool present_maxRejects;
    int maxRejects;
    bool present_enforcePeriod;
    int enforcePeriod;
    bool present_nss24GCap;
    int nss24GCap;
    bool present_nss5GCap;
    int nss5GCap;
    bool present_busyPpdusPerMinute;
    int busyPpdusPerMinute;
    bool present_busyOverrideProbeSnr;
    int busyOverrideProbeSnr;
    bool present_busyOverrideThroughputMbps;
    int busyOverrideThroughputMbps;
}DpClientSteering_t;

typedef struct {
    bool present_kickType;
    sp_client_kick_t kickType;
    bool present_stickyKickType;
    sp_client_kick_t stickyKickType;
    bool present_lwm;
    int lwm;
    bool present_lwm2;
    int lwm2;
    bool present_lwm3;
    int lwm3;
    bool present_hwm;
    int hwm;
    bool present_hwm2;
    int hwm2;
    bool present_hwm3;
    int hwm3;
    bool present_maxRejects;
    int maxRejects;
    bool present_pref_5g;
    sp_client_pref_allowed    pref_5g;
    bool present_pref_6g;
    sp_client_pref_allowed    pref_6g;
    bool present_gw_only_6g;
    DpGwOnlyOverlay6g         *gw_only_6g;
}DpBandSteering6G_t;

typedef struct{
    char description[100];
    int id;
    bool present_bandSteering;
    DpBandSteering_t *bandSteering;
    bool present_bandSteering6g;
    DpBandSteering6G_t *bandSteering6g;
    bool present_clientSteering;
    DpClientSteering_t *clientSteering;
}DeviceSpecificProfile_t;

typedef struct{
    DeviceSpecificProfile_t *profiles;
    int count;
}DeviceSpecificProfiles_t;

typedef struct
{
    char         *name;
    char         *value;
    uint32_t     value_size;
    uint16_t     type;
} mwoparam_t;

typedef struct {
    sp_band_steering_t *band_steer;
    sp_band_steering_t *band_steer_6g;
    sp_client_steering_t *client_steering;
    sp_dfs_t       *dfs;
} sp_defaultdoc_t;

typedef struct {
    char *       subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
    sp_defaultdoc_t *sp_default;
    DeviceSpecificProfiles_t *device;
} sp_doc_t;

typedef struct {
    char         mac[18];
    int          id;
}clients_t;

typedef struct {
    char *       subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
    int          count;
    clients_t    *clients;
} dp_doc_t;

typedef struct {
    int *ko_channel_160;
    int n_ko_channel_160;
    int *ko_channel_320;
    int n_ko_channel_320;
    int *ko_channel_80;
    int n_ko_channel_80;
} radio_keepout_channels;

typedef struct {
    int priority;
    char *plan_id;
    struct {
        radio_keepout_channels radio6G;
        radio_keepout_channels radio5G;
        radio_keepout_channels radio2G;
    } config;
} channel_keep_out;

typedef enum {
    HT_UNSUPPORTED,
    HT_20,
    HT_80,
    HT_160,
    HT_320
}channel_bandwidth;

typedef struct {
    uint8_t radio6G_bandwidth;
    uint16_t radio6G_channel;
    uint8_t radio5G_bandwidth;
    uint16_t radio5G_channel;
    uint8_t radio2G_bandwidth;
    uint16_t radio2G_channel;
}radio_channel_config;

typedef struct {
    int priority;
    char *plan_id;
    uint64_t expiry;
    bool is_blob_expired;
    radio_channel_config *radio_config;
} HD_recc;

typedef struct {
    char *       subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
    int          count;
    channel_keep_out    *keepout_channel_list;
    HD_recc             *HD_recc;
}channel_plan_doc_t;

typedef union {
    char *string_value;
    bool boolean_value;
    int int_value;
} Value_t;

typedef struct {
    char *name;
    eValueType type;
    Value_t value;
}configs_t;

typedef struct {
    char *       subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
    int          count;
    configs_t    *config_data;
} configs_doc_t;

typedef struct {
    bool         mesh_enable;
    bool         ethernetbackhaul_enable;
    char         * subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
} meshbackhauldoc_t;

typedef struct {
    bool         wfm_enable;
    char         * subdoc_name;
    uint32_t     version;
    uint16_t     transaction_id;
} wfm_doc_t;

typedef struct
{
    eBlobType type;           // Enum blob type
    const char      *blob_name_str;     // Blob name string
}meshblob_name_t;

typedef struct {
    bool mesh_enable;
    bool ethernetbackhaul_enable;
} t_cache;

typedef struct {
    radio_type_t radio_type;
    int          channel;
    float        tot_active_interf_min;
    float        tot_idle_interf_min;
    float        avg_active_interf;
    float        avg_idle_interf;
}interference_t;

typedef struct {
    char *            subdoc_name;
    uint32_t          version;
    uint16_t          transaction_id;
    int               count;
    interference_t    *ai_data;
} ai_doc_t;


uint32_t getBlobVersion(char* subdoc);
int setBlobVersion(char* subdoc,uint32_t version);
void webConfigFrameworkInit() ;

void clear_mb_cache(t_cache *tmp_mb_cache);
void print_mb_cache(t_cache *tmp_mb_cache);
int clear_mb_cache_DB(t_cache *tmp_mb_cache);
int apply_mb_cache_ToDB(t_cache *tmp_mb_cache);
int set_meshbackhaul_conf(meshbackhauldoc_t *mb,t_cache *cache);
void backup_mb_cache(t_cache *tmp_mb_cache,t_cache *tmp_mb_cache_bkup);

void init_mb_cache(t_cache *tmp_mb_cache);

pErr Process_MB_WebConfigRequest(void *Data);
int rollback_MeshBackhaul() ;
void freeResources_MeshBackhaul(void *arg);
size_t webconf_Mesh_Timeout_Handler(size_t numOfEntries);
void mesh_blob_dump(meshbackhauldoc_t *mb);
bool  mesh_msgpack_decode(char* pString, int decode_size, eBlobType type);
void deviceprofile_blob_dump(dp_doc_t *dp);
void steeringprofile_blob_dump(sp_doc_t *sp);
bool push_blob_request(char * name, void *data, uint32_t version, uint16_t transaction_id,eBlobType blob_type);
void channel_keepout_doc_init(char *buffer);
void channel_keepout_radio_config_init(cJSON * json_radio,radio_keepout_channels *radio);
char *channel_keepout_event_data_get(channel_plan_doc_t *channel_plan_data);
char * hd_recommendation_event_data_get(channel_plan_doc_t *channel_plan_data);
bool channel_keepout_init();
bool hd_recommendation_init();
void free_channel_keepout_global();
void free_channel_plan_global();
void free_hd_recc_global();
#endif
