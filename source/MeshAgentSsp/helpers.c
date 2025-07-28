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

#include <errno.h>
#include <string.h>
#include <msgpack.h>
#include "ccsp_trace.h"
#include "meshagent.h"
#include "cosa_webconfig_api.h"
#include "helpers.h"
#include "safec_lib_common.h"
#include "cosa_meshagent_internal.h"
#include "cosa_apis_util.h"
#include <cjson/cJSON.h>
/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define MB_ERROR                   -1
#define STEERING_CONFIG_FILE       "/nvram/steering.json"
#define DEVICE_CONFIG_FILE         "/nvram/device_profile.json"
#define INTERFERENCE_CONFIG_FILE   "/nvram/mwo/sa/lts_deployment_stats"
/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/

extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;

meshblob_name_t  meshBlobNameArr[] = {
    {MESH,                             "mesh"},
    {STEERING_PROFILE_DEFAULT,         "meshsteeringprofiles"},
    {DEVICE,                           "DeviceToSteeringProfile"},
    {WIFI_CONFIG,                      "wificonfig_stat"},
    {CONFIGS,                          "mwoconfigs"},
    {INTERFERENCE,                     "interference"},
    {WIFI_MOTION,                      "wifimotionsettings"},
    {CHANNEL_PLAN_DATA,                "channelplan"}
};

static c_item_t map_ovsdb_reject_detection[] = {
    C_ITEM_STR(SP_CLIENT_REJECT_NONE,           "none"),
    C_ITEM_STR(SP_CLIENT_REJECT_PROBE_ALL,      "probe_all"),
    C_ITEM_STR(SP_CLIENT_REJECT_PROBE_NULL,     "probe_null"),
    C_ITEM_STR(SP_CLIENT_REJECT_PROBE_DIRECT,   "probe_direct"),
    C_ITEM_STR(SP_CLIENT_REJECT_AUTH_BLOCKED,   "auth_block")
};

static c_item_t map_ovsdb_kick_type[] = {
    C_ITEM_STR(SP_CLIENT_KICK_NONE,             "none"),
    C_ITEM_STR(SP_CLIENT_KICK_DISASSOC,         "disassoc"),
    C_ITEM_STR(SP_CLIENT_KICK_DEAUTH,           "deauth"),
    C_ITEM_STR(SP_CLIENT_KICK_BSS_TM_REQ,       "bss_tm_req"),
    C_ITEM_STR(SP_CLIENT_KICK_RRM_BR_REQ,       "rrm_br_req"),
    C_ITEM_STR(SP_CLIENT_KICK_BTM_DISASSOC,     "btm_disassoc"),
    C_ITEM_STR(SP_CLIENT_KICK_BTM_DEAUTH,       "btm_deauth"),
    C_ITEM_STR(SP_CLIENT_KICK_RRM_DISASSOC,     "rrm_disassoc"),
    C_ITEM_STR(SP_CLIENT_KICK_RRM_DEAUTH,       "rrm_deauth")
};

static c_item_t map_ovsdb_pref_5g_allowed[] = {
    C_ITEM_STR(SP_CLIENT_PREF_ALLOWED_NEVER,              "never" ),
    C_ITEM_STR(SP_CLIENT_PREF_ALLOWED_HWM,                "hwm"   ),
    C_ITEM_STR(SP_CLIENT_PREF_ALLOWED_ALWAYS,             "always"),
    C_ITEM_STR(SP_CLIENT_PREF_ALLOWED_NON_DFS,            "nonDFS")
};

static c_item_t map_mwo_configs_type[] = {
    C_ITEM_STR(TYPE_STRING,              "string" ),
    C_ITEM_STR(TYPE_BOOLEAN,             "boolean"),
    C_ITEM_STR(TYPE_INT,                 "int")
};

static c_item_t map_ovsdb_radio_type[] = {
    C_ITEM_STR(RADIO_TYPE_NONE,      "none"),
    C_ITEM_STR(RADIO_TYPE_2G,        "2.4G"),
    C_ITEM_STR(RADIO_TYPE_5G,        "5G"),
    C_ITEM_STR(RADIO_TYPE_5GL,       "5GL"),
    C_ITEM_STR(RADIO_TYPE_5GU,       "5GU"),
    C_ITEM_STR(RADIO_TYPE_6G,         "6G")
};

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
msgpack_object* __finder( const char *name, 
                          msgpack_object_type expect_type,
                          msgpack_object_map *map );
c_item_t * _c_get_item_by_str(c_item_t *list, int list_sz, const char *str);
char * _c_get_str_by_key(c_item_t *list, int list_sz, int key);
int process_bsparams( sp_defaultdoc_t *steer, msgpack_object_map *map, bool is_6g );
int process_device_profile( DeviceSpecificProfiles_t *device, msgpack_object_array *array );
typedef int (*process_fn_t)(void *, int, ...);
typedef void (*destroy_fn_t)(void *);

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
/**
 *  Simple helper function that decodes the msgpack, then checks for a few
 *  sanity items (including an optional wrapper map) before calling the process
 *  argument passed in.  This also allocates the structure for the caller.
 *
 *  @param buf          the buffer to decode
 *  @param len          the length of the buffer in bytes
 *  @param struct_size  the size of the structure to allocate and pass to process
 *  @param wrapper      the optional wrapper to look for & enforce
 *  @param expect_type  the type of object expected
 *  @param optional     if the inner wrapper layer is optional
 *  @param process      the process function to call if successful
 *  @param destroy      the destroy function to call if there was an error
 *
 *  @returns the object after process has done it's magic to it on success, or
 *           NULL on error
 */

void* helper_convert( const void *buf, size_t len,
                      size_t struct_size, const char *wrapper,
                      msgpack_object_type expect_type, bool optional,
                      process_fn_t process,
                      destroy_fn_t destroy )
{
    void *p = malloc( struct_size );

    if( NULL == p )
    {
        errno = HELPERS_OUT_OF_MEMORY;
    }
    else
    {
        memset( p, 0, struct_size );
        if( NULL != buf && 0 < len && process != NULL && destroy != NULL )
        {
            size_t offset = 0;
            msgpack_unpacked msg;
            msgpack_unpack_return mp_rv;

            msgpack_unpacked_init( &msg );

            /* The outermost wrapper MUST be a map. */
            mp_rv = msgpack_unpack_next( &msg, (const char*) buf, len, &offset );
            if( (MSGPACK_UNPACK_SUCCESS == mp_rv) && (0 != offset) &&
                (MSGPACK_OBJECT_MAP == msg.data.type) )
            {
                msgpack_object *inner;
                msgpack_object *subdoc_name;
                msgpack_object *version;
                msgpack_object *transaction_id;
                if( NULL != wrapper && 0 != strcmp(wrapper,"parameters"))
                {
                    if((strcmp(wrapper,"DeviceToSteeringProfile")== 0) ||
                       (strcmp(wrapper,"mwoconfigs") == 0) ||  (strcmp(wrapper,"interference") == 0) ||
                       (strcmp(wrapper,"channelplan") == 0))
                        inner =  &msg.data.via.map.ptr->val;
                    else
                        inner = __finder( wrapper, expect_type, &msg.data.via.map );

                    subdoc_name =  __finder( "subdoc_name", expect_type, &msg.data.via.map );
                    version =  __finder( "version", expect_type, &msg.data.via.map );
                    transaction_id =  __finder( "transaction_id", expect_type, &msg.data.via.map );
                    if( ((NULL != inner) && (0 == (process)(p,4, inner, subdoc_name, version, transaction_id))) ||
                              ((true == optional) && (NULL == inner)) )
                    {
                         msgpack_unpacked_destroy( &msg );
                         errno = HELPERS_OK;
                         return p;
                    }
                    else
                    {
                         errno = HELPERS_INVALID_FIRST_ELEMENT;
                    }
                }
              }
            msgpack_unpacked_destroy( &msg );
            if(NULL!=p)
            {
               (destroy)( p );
                p = NULL;
            }
        }
    }
    return p;
}

cJSON* create_clientSteering_object(DpClientSteering_t *client)
{
    if(client == NULL)
    {
        MeshInfo("%s:client is NULL\n",__FUNCTION__);
        return NULL;
    }
    cJSON *clientSteering = cJSON_CreateObject();
    // Add fields to clientSteering based on the id
    if(client)
    {
        if(client->present_enable)
            cJSON_AddBoolToObject(clientSteering, "enable",client->enable);
        if(client->present_overrideDefault11kv)
            cJSON_AddBoolToObject(clientSteering, "overrideDefault11kv",client->overrideDefault11kv);
        if(client->present_retryTimeoutHours)
            cJSON_AddNumberToObject(clientSteering, "retryTimeoutHours", client->retryTimeoutHours);
        if(client->present_maxPoorThroughputCount)
            cJSON_AddNumberToObject(clientSteering, "maxPoorThroughputCount",client->maxPoorThroughputCount );
        if(client->present_kickType)
            cJSON_AddStringToObject(clientSteering, "kickType", c_get_str_by_key(map_ovsdb_kick_type,client->kickType));
        if(client->present_specKickType)
            cJSON_AddStringToObject(clientSteering, "specKickType", c_get_str_by_key(map_ovsdb_kick_type,client->specKickType));
        if(client->present_lwm2)
            cJSON_AddNumberToObject(clientSteering, "lwm2",client->lwm2);
        if(client->present_lwm3)
            cJSON_AddNumberToObject(clientSteering, "lwm3", client->lwm3);
        if(client->present_hwm2)
            cJSON_AddNumberToObject(clientSteering, "hwm2", client->hwm2);
        if(client->present_hwm3)
            cJSON_AddNumberToObject(clientSteering, "hwm3", client->hwm3);
        if(client->present_nss24GCap)
            cJSON_AddNumberToObject(clientSteering, "nss24GCap", client->nss24GCap);
        if(client->present_nss5GCap)
            cJSON_AddNumberToObject(clientSteering, "nss5GCap", client->nss5GCap);
        if(client->present_busyPpdusPerMinute)
            cJSON_AddNumberToObject(clientSteering, "busyPpdusPerMinute", client->busyPpdusPerMinute);
        if(client->present_busyOverrideProbeSnr)
            cJSON_AddNumberToObject(clientSteering, "busyOverrideProbeSnr", client->busyOverrideProbeSnr);
        if(client->present_busyOverrideThroughputMbps)
            cJSON_AddNumberToObject(clientSteering, "busyOverrideThroughputMbps", client->busyOverrideThroughputMbps);
        if(client->present_enforcePeriod)
            cJSON_AddNumberToObject(clientSteering, "enforcePeriod", client->enforcePeriod);
        if(client->present_maxRejects)
            cJSON_AddNumberToObject(clientSteering, "maxRejects", client->maxRejects);
    }
    return clientSteering;
}

cJSON* create_bandSteering_object(DpBandSteering_t *steering)
{
 
    if(steering == NULL)
    {
        MeshInfo("%s:steering is NULL\n",__FUNCTION__);
        return NULL;
    }

    cJSON *bandSteering = cJSON_CreateObject();

    if(steering)
    {
        if(steering->present_enable)
            cJSON_AddBoolToObject(bandSteering, "enable",steering->enable);
        if(steering->present_kickUponIdleOnly)
            cJSON_AddBoolToObject(bandSteering, "kickUponIdleOnly",steering->kickUponIdleOnly);
        if(steering->present_preAssociationAuthBlock)
            cJSON_AddBoolToObject(bandSteering, "preAssociationAuthBlock",steering->preAssociationAuthBlock);
        if(steering->present_hwm)
            cJSON_AddNumberToObject(bandSteering, "hwm",steering->hwm);
        if(steering->present_lwm)
            cJSON_AddNumberToObject(bandSteering, "lwm", steering->lwm);
        if(steering->present_kickType)
            cJSON_AddStringToObject(bandSteering, "kickType",c_get_str_by_key(map_ovsdb_kick_type,steering->kickType));
        if(steering->present_stickyKickType)
            cJSON_AddStringToObject(bandSteering, "stickyKickType",c_get_str_by_key(map_ovsdb_kick_type,steering->stickyKickType));
        if(steering->present_gwOnly)
        {
            cJSON *gwOnly  = cJSON_CreateObject();
            cJSON_AddItemToObject(bandSteering, "gwOnly", gwOnly);
            cJSON_AddNumberToObject(gwOnly, "lwm",steering->gwOnly->lwm);
        }
    }
    return bandSteering;
}

cJSON* create_bandSteering6G_object(DpBandSteering6G_t *dp_bs_6g)
{
    if(dp_bs_6g == NULL)
    {
        MeshInfo("%s:dp_bs_6g is NULL\n",__FUNCTION__);
        return NULL;
    }
    cJSON *bandSteering6G = cJSON_CreateObject();

    if(dp_bs_6g)
    {
        if (dp_bs_6g->present_hwm)
            cJSON_AddNumberToObject(bandSteering6G, "hwm",dp_bs_6g->hwm);
        if (dp_bs_6g->present_hwm2)
            cJSON_AddNumberToObject(bandSteering6G, "hwm2", dp_bs_6g->hwm2);
        if (dp_bs_6g->present_hwm3)
            cJSON_AddNumberToObject(bandSteering6G, "hwm3", dp_bs_6g->hwm3);
        if (dp_bs_6g->present_pref_5g)
            cJSON_AddStringToObject(bandSteering6G, "preferred5g",c_get_str_by_key(map_ovsdb_pref_5g_allowed,dp_bs_6g->pref_5g));
        if (dp_bs_6g->present_pref_6g)
            cJSON_AddStringToObject(bandSteering6G, "preferred6g",c_get_str_by_key(map_ovsdb_pref_5g_allowed,dp_bs_6g->pref_6g));
        if (dp_bs_6g->present_lwm)
            cJSON_AddNumberToObject(bandSteering6G, "lwm", dp_bs_6g->lwm);
        if (dp_bs_6g->present_lwm2)
            cJSON_AddNumberToObject(bandSteering6G, "lwm2", dp_bs_6g->lwm2);
        if (dp_bs_6g->present_lwm3)
            cJSON_AddNumberToObject(bandSteering6G, "lwm3", dp_bs_6g->lwm3);
        if (dp_bs_6g->present_maxRejects)
            cJSON_AddNumberToObject(bandSteering6G, "maxRejects", dp_bs_6g->maxRejects);
        if (dp_bs_6g->present_kickType)
            cJSON_AddStringToObject(bandSteering6G, "kickType",c_get_str_by_key(map_ovsdb_kick_type,dp_bs_6g->kickType));
        if (dp_bs_6g->present_stickyKickType)
           cJSON_AddStringToObject(bandSteering6G, "stickyKickType",c_get_str_by_key(map_ovsdb_kick_type,dp_bs_6g->stickyKickType));
        if(dp_bs_6g->present_gw_only_6g)
        {
            cJSON *gwOnlyOverlay  = cJSON_CreateObject();
            cJSON_AddItemToObject(bandSteering6G, "gwOnlyOverlay", gwOnlyOverlay);
            cJSON_AddStringToObject(gwOnlyOverlay, "preferred6g",c_get_str_by_key(map_ovsdb_pref_5g_allowed,dp_bs_6g->gw_only_6g->pref_6g));
        }
    }
    return bandSteering6G;
}

cJSON* create_profile_object(clients_t    *clients)
{
    cJSON *profile = cJSON_CreateObject();
    cJSON_AddStringToObject(profile, "mac_addr", clients->mac);
    cJSON_AddNumberToObject(profile, "prof_id",clients->id);
    return profile;
}

char *steering_profile_event_data_get()
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "event_type", "MWO_TOS_CONFIGURATION");
    cJSON *event_data = cJSON_CreateObject();
    cJSON_AddStringToObject(event_data, "message", g_pMeshAgent->meshSteeringProfileDefault?"Default profile updated.":"Default profile Not Updated");
    cJSON_AddItemToObject(root, "event_data", event_data);
    char *json_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_string;
}

char *client_profile_event_data_get()
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "event_type", "MWO_CLIENT_TO_PROFILE_MAP_EVENT");
    cJSON *event_data = cJSON_CreateObject();
    cJSON_AddStringToObject(event_data, "message",g_pMeshAgent->meshClientProfileReceived?"Client mapping Updated":"Client mapping Not Updated");
    cJSON_AddItemToObject(root, "event_data", event_data);
    char *json_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json_string;
}

void save_device_profile_tofile(dp_doc_t *dp)
{
    int i;
    cJSON *root = cJSON_CreateObject();
    cJSON *clienttosteeringprofile = cJSON_CreateArray();

    cJSON_AddItemToObject(root, "clienttosteeringprofile", clienttosteeringprofile);

    for (i = 0; i < dp->count; i++) {
        cJSON_AddItemToArray(clienttosteeringprofile, create_profile_object((dp->clients+i)));
    }
    char *string = cJSON_PrintUnformatted(root);
    FILE *file = fopen(DEVICE_CONFIG_FILE, "w");

    if (file == NULL) {
        MeshInfo("Error opening file!\n");
        return ;
    }

    fprintf(file, "%s", string);

    fclose(file);

    free(string);
    cJSON_Delete(root);
}

cJSON* create_ai_profile_object(interference_t    *data)
{
    cJSON *profile = cJSON_CreateObject();
    cJSON_AddNumberToObject(profile, "channel",data->channel);
    cJSON_AddStringToObject(profile, "radio_type", c_get_str_by_key(map_ovsdb_radio_type,data->radio_type));
    cJSON_AddNumberToObject(profile, "tot_active_if_min", data->tot_active_interf_min);
    cJSON_AddNumberToObject(profile, "tot_idle_if_min", data->tot_idle_interf_min);
    cJSON_AddNumberToObject(profile, "avg_active_if", data->avg_active_interf);
    cJSON_AddNumberToObject(profile, "avg_idle_if", data->avg_idle_interf);
    return profile;
}

void save_ai_profile_tofile(ai_doc_t *ai)
{
    int i;
    cJSON *root = cJSON_CreateObject();
    cJSON *interference = cJSON_CreateArray();

    cJSON_AddItemToObject(root, "interference", interference);

    for (i = 0; i < ai->count; i++) {
        cJSON_AddItemToArray(interference, create_ai_profile_object((ai->ai_data+i)));
    }
    char *string = cJSON_PrintUnformatted(root);
    FILE *file = fopen(INTERFERENCE_CONFIG_FILE, "w");

    if (file == NULL) {
        MeshInfo("Error opening file!\n");
        return ;
    }

    fprintf(file, "%s", string);

    fclose(file);

    free(string);
    cJSON_Delete(root);
}

void save_channel_keepout_tofile(char * payload) {
    if (!payload) {
        MeshError("%s payload is NULL\n",__FUNCTION__);
        return;
    }
    FILE *file = fopen(CHANNEL_KEEPOUT_FILE, "w");

    if (file == NULL) {
        MeshInfo("Error opening file!\n");
        return ;
    }
 
    if (fprintf(file, "%s", payload) < 0) {
        MeshError("%s failed to write to a file.\n",__FUNCTION__);
    }
    fclose(file);
}

void save_hdrecc_tofile(char * payload) {
    if (!payload) {
        MeshError("%s payload is NULL\n",__FUNCTION__);
        return;
    }
    FILE *file = fopen(HD_RECC_FILE, "w");

    if (file == NULL) {
        MeshInfo("Error opening file!\n");
        return ;
    }
 
    if (fprintf(file, "%s", payload) < 0) {
        MeshError("%s failed to write to a file.\n",__FUNCTION__);
    }
    fclose(file);
}

void save_steering_profile_tofile(sp_doc_t *sp)
{
    // Create JSON Objects
    if(sp->sp_default == NULL)
    {
       MeshInfo("%s:sp_default is NULL\n",__FUNCTION__);
       return;
    }
    if(sp->sp_default->band_steer == NULL)
        MeshInfo("%s:band_steer is NULL\n",__FUNCTION__);
    if(sp->sp_default->band_steer_6g == NULL)
        MeshInfo("%s:band_steer is NULL\n",__FUNCTION__);
    if(sp->sp_default->client_steering == NULL)
        MeshInfo("%s:band_steer is NULL\n",__FUNCTION__);
    if(sp->sp_default->dfs == NULL)
        MeshInfo("%s:dfs is NULL\n",__FUNCTION__);
    if(sp->device == NULL)
        MeshInfo("%s:device is NULL\n",__FUNCTION__);

    cJSON *root = cJSON_CreateObject();
    cJSON *meshsteeringprofiles = cJSON_CreateObject();
    cJSON *steeringprofiledefaults = cJSON_CreateObject();
    cJSON *bandSteering = cJSON_CreateObject();
    cJSON *dot11vParamBandSteering = cJSON_CreateObject();
    cJSON *dot11vParamStickyClientSteering = cJSON_CreateObject();
    cJSON *gwOnlyOverlay = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "meshsteeringprofiles", meshsteeringprofiles);
    cJSON_AddItemToObject(meshsteeringprofiles, "steeringprofiledefaults", steeringprofiledefaults);
    cJSON_AddItemToObject(steeringprofiledefaults, "bandSteering", bandSteering);
    if (sp->sp_default->band_steer)
    {
        cJSON_AddBoolToObject(bandSteering, "enable", sp->sp_default->band_steer->enable);
        cJSON_AddNumberToObject(bandSteering, "backoffSeconds", sp->sp_default->band_steer->backoff_second);
        cJSON_AddBoolToObject(bandSteering, "steerDuringBackoff", sp->sp_default->band_steer->steer_during_backoff);
        cJSON_AddNumberToObject(bandSteering, "backoffExpBase", sp->sp_default->band_steer->backoff_exp_base);
        cJSON_AddNumberToObject(bandSteering, "stickyKickGuardTime", sp->sp_default->band_steer->sticky_kick_guard_time);
        cJSON_AddNumberToObject(bandSteering, "stickyKickBackoffTime", sp->sp_default->band_steer->sticky_kick_backoff_time);
        cJSON_AddNumberToObject(bandSteering, "hwm", sp->sp_default->band_steer->hwm);
        cJSON_AddNumberToObject(bandSteering, "kickReason",sp->sp_default->band_steer->kick_reason);
        cJSON_AddStringToObject(bandSteering, "kickType", c_get_str_by_key(map_ovsdb_kick_type,sp->sp_default->band_steer->kick_type));
        cJSON_AddNumberToObject(bandSteering, "stickyKickReason", sp->sp_default->band_steer->sticky_kick_reason);
        cJSON_AddStringToObject(bandSteering, "stickyKickType", c_get_str_by_key(map_ovsdb_kick_type,sp->sp_default->band_steer->sticky_kick_type));
        cJSON_AddStringToObject(bandSteering, "preferred5g", c_get_str_by_key(map_ovsdb_pref_5g_allowed,sp->sp_default->band_steer->pref_allowed));
        cJSON_AddStringToObject(bandSteering, "preferred6g", c_get_str_by_key(map_ovsdb_pref_5g_allowed,sp->sp_default->band_steer->pref_6g));
        cJSON_AddBoolToObject(bandSteering, "preAssociationAuthBlock", sp->sp_default->band_steer->pre_assoc_auth_block);
        cJSON_AddNumberToObject(bandSteering, "lwm", sp->sp_default->band_steer->lwm);
        cJSON_AddNumberToObject(bandSteering, "bottomLwm", sp->sp_default->band_steer->bottomLwm);
        cJSON_AddNumberToObject(bandSteering, "maxRejects", sp->sp_default->band_steer->max_rejects);
        cJSON_AddStringToObject(bandSteering, "rejectDetection", c_get_str_by_key(map_ovsdb_reject_detection,sp->sp_default->band_steer->reject_detection));
        cJSON_AddNumberToObject(bandSteering, "rejectsTimeoutSeconds",sp->sp_default->band_steer->max_rejects_period);
        cJSON_AddBoolToObject(bandSteering, "kickUponIdleOnly", sp->sp_default->band_steer->kick_upon_idle);
        cJSON_AddNumberToObject(bandSteering, "kickDebouncePeriod", sp->sp_default->band_steer->kick_debounce_period);
        cJSON_AddNumberToObject(bandSteering, "stickyKickDebouncePeriod", sp->sp_default->band_steer->sticky_kick_debounce_period);
        cJSON_AddBoolToObject(bandSteering, "neighborListFilterByBeaconReport", sp->sp_default->band_steer->neighbor_list_filter_by_beacon_report);
        cJSON_AddBoolToObject(bandSteering, "neighborListFilterByBTMStatus", sp->sp_default->band_steer->neighborListFilterByBTMStatus);
        cJSON_AddNumberToObject(bandSteering, "btmMaxNeighbors", sp->sp_default->band_steer->btmMaxNeighbors);
        cJSON_AddNumberToObject(bandSteering, "btmMaxNeighbors6g", sp->sp_default->band_steer->btmMaxNeighbors6g);

        cJSON_AddItemToObject(bandSteering, "dot11vParamBandSteering", dot11vParamBandSteering);
        if(sp->sp_default->band_steer->steering_btm_params)
        {
            cJSON_AddNumberToObject(dot11vParamBandSteering, "validityIntervalInTBTT",sp->sp_default->band_steer->steering_btm_params->valid_interval_tbtt);
            cJSON_AddNumberToObject(dot11vParamBandSteering, "abridged", sp->sp_default->band_steer->steering_btm_params->abridged);
            cJSON_AddNumberToObject(dot11vParamBandSteering, "preferred",sp->sp_default->band_steer->steering_btm_params->pref);
            cJSON_AddNumberToObject(dot11vParamBandSteering, "disassociationImminent",sp->sp_default->band_steer->steering_btm_params->disassociation_imminent);
            cJSON_AddNumberToObject(dot11vParamBandSteering, "bssTermination", sp->sp_default->band_steer->steering_btm_params->bss_termination);
            cJSON_AddNumberToObject(dot11vParamBandSteering, "retryCount", sp->sp_default->band_steer->steering_btm_params->retry_count);
            cJSON_AddNumberToObject(dot11vParamBandSteering, "retryInterval", sp->sp_default->band_steer->steering_btm_params->retry_interval);
        }

        cJSON_AddItemToObject(bandSteering, "dot11vParamStickyClientSteering", dot11vParamStickyClientSteering);
        if(sp->sp_default->band_steer->sticky_btm_params)
        {
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering, "validityIntervalInTBTT", sp->sp_default->band_steer->sticky_btm_params->valid_interval_tbtt);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering, "abridged", sp->sp_default->band_steer->sticky_btm_params->abridged);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering, "preferred", sp->sp_default->band_steer->sticky_btm_params->pref);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering, "disassociationImminent", sp->sp_default->band_steer->sticky_btm_params->disassociation_imminent);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering, "bssTermination", sp->sp_default->band_steer->sticky_btm_params->bss_termination);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering, "retryCount", sp->sp_default->band_steer->sticky_btm_params->retry_count);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering, "retryInterval", sp->sp_default->band_steer->sticky_btm_params->retry_interval);
            cJSON_AddBoolToObject(dot11vParamStickyClientSteering, "includeNeighbors",sp->sp_default->band_steer->sticky_btm_params->include_neighbors);
        }

        cJSON_AddItemToObject(bandSteering, "gwOnlyOverlay", gwOnlyOverlay);
        if(sp->sp_default->band_steer->for_gw_only)
        {
            cJSON_AddStringToObject(gwOnlyOverlay, "preferred5g", c_get_str_by_key(map_ovsdb_pref_5g_allowed,sp->sp_default->band_steer->for_gw_only->pref_5g));
            cJSON_AddNumberToObject(gwOnlyOverlay, "lwm", sp->sp_default->band_steer->for_gw_only->lwm);
        }
    }

    cJSON *bandSteering6G = cJSON_CreateObject();
    cJSON *dot11vParamBandSteering_6g = cJSON_CreateObject();
    cJSON *dot11vParamStickyClientSteering_6g = cJSON_CreateObject();
    cJSON *gwOnlyOverlay_6g = cJSON_CreateObject();

    cJSON_AddItemToObject(steeringprofiledefaults, "bandSteering6G", bandSteering6G);
    if (sp->sp_default->band_steer_6g)
    {
        cJSON_AddBoolToObject(bandSteering6G, "enable", sp->sp_default->band_steer_6g->enable);
        cJSON_AddNumberToObject(bandSteering6G, "backoffSeconds",sp->sp_default->band_steer_6g->backoff_second);
        cJSON_AddBoolToObject(bandSteering6G, "steerDuringBackoff", sp->sp_default->band_steer_6g->steer_during_backoff);
        cJSON_AddNumberToObject(bandSteering6G, "backoffExpBase", sp->sp_default->band_steer_6g->backoff_exp_base);
        cJSON_AddNumberToObject(bandSteering6G, "stickyKickGuardTime", sp->sp_default->band_steer_6g->sticky_kick_guard_time);
        if (sp->sp_default->band_steer_6g->band_steering_6g)
            cJSON_AddNumberToObject(bandSteering6G, "steeringKickBackOffTime", sp->sp_default->band_steer_6g->band_steering_6g->steerDuringBackoff);
        cJSON_AddNumberToObject(bandSteering6G, "stickyKickBackoffTime", sp->sp_default->band_steer_6g->sticky_kick_backoff_time);
        cJSON_AddNumberToObject(bandSteering6G, "hwm",sp->sp_default->band_steer_6g->hwm );
        cJSON_AddNumberToObject(bandSteering6G, "hwm2", sp->sp_default->band_steer_6g->band_steering_6g->hwm2);
        cJSON_AddNumberToObject(bandSteering6G, "hwm3", sp->sp_default->band_steer_6g->band_steering_6g->hwm3);
        cJSON_AddNumberToObject(bandSteering6G, "kickReason", sp->sp_default->band_steer_6g->kick_reason);
        cJSON_AddStringToObject(bandSteering6G, "kickType", c_get_str_by_key(map_ovsdb_kick_type,sp->sp_default->band_steer_6g->kick_type));
        cJSON_AddNumberToObject(bandSteering6G, "stickyKickReason", sp->sp_default->band_steer_6g->sticky_kick_reason);
        cJSON_AddStringToObject(bandSteering6G, "stickyKickType", c_get_str_by_key(map_ovsdb_kick_type,sp->sp_default->band_steer_6g->sticky_kick_type));
        cJSON_AddStringToObject(bandSteering6G, "preferred5g", c_get_str_by_key(map_ovsdb_pref_5g_allowed,sp->sp_default->band_steer_6g->pref_allowed));
        cJSON_AddStringToObject(bandSteering6G, "preferred6g",c_get_str_by_key(map_ovsdb_pref_5g_allowed,sp->sp_default->band_steer_6g->pref_6g));
        cJSON_AddBoolToObject(bandSteering6G, "preAssociationAuthBlock",sp->sp_default->band_steer_6g->pre_assoc_auth_block);
        cJSON_AddNumberToObject(bandSteering6G, "lwm", sp->sp_default->band_steer_6g->lwm);
        cJSON_AddNumberToObject(bandSteering6G, "lwm2", sp->sp_default->band_steer_6g->band_steering_6g->lwm2);
        cJSON_AddNumberToObject(bandSteering6G, "lwm3", sp->sp_default->band_steer_6g->band_steering_6g->lwm3);
        cJSON_AddNumberToObject(bandSteering6G, "bottomLwm", sp->sp_default->band_steer_6g->bottomLwm);
        cJSON_AddNumberToObject(bandSteering6G, "maxRejects", sp->sp_default->band_steer_6g->max_rejects);
        cJSON_AddStringToObject(bandSteering6G, "rejectDetection", c_get_str_by_key(map_ovsdb_reject_detection,sp->sp_default->band_steer_6g->reject_detection));
        cJSON_AddNumberToObject(bandSteering6G, "rejectsTimeoutSeconds",sp->sp_default->band_steer_6g->max_rejects_period);
        cJSON_AddBoolToObject(bandSteering6G, "kickUponIdleOnly", sp->sp_default->band_steer_6g->kick_upon_idle);
        cJSON_AddNumberToObject(bandSteering6G, "kickDebouncePeriod", sp->sp_default->band_steer_6g->kick_debounce_period);
        cJSON_AddNumberToObject(bandSteering6G, "stickyKickDebouncePeriod", sp->sp_default->band_steer_6g->sticky_kick_debounce_period);
        cJSON_AddBoolToObject(bandSteering6G, "neighborListFilterByBeaconReport", sp->sp_default->band_steer_6g->neighbor_list_filter_by_beacon_report);
        cJSON_AddBoolToObject(bandSteering6G, "neighborListFilterByBTMStatus",sp->sp_default->band_steer_6g->neighborListFilterByBTMStatus);
        cJSON_AddNumberToObject(bandSteering6G, "btmMaxNeighbors", sp->sp_default->band_steer_6g->btmMaxNeighbors);
        cJSON_AddNumberToObject(bandSteering6G, "btmMaxNeighbors6g", sp->sp_default->band_steer_6g->btmMaxNeighbors6g);

        cJSON_AddItemToObject(bandSteering6G, "dot11vParamBandSteering", dot11vParamBandSteering_6g);
        if(sp->sp_default->band_steer_6g->steering_btm_params)
        {
            cJSON_AddNumberToObject(dot11vParamBandSteering_6g, "validityIntervalInTBTT",sp->sp_default->band_steer_6g->steering_btm_params->valid_interval_tbtt);
            cJSON_AddNumberToObject(dot11vParamBandSteering_6g, "abridged", sp->sp_default->band_steer_6g->steering_btm_params->abridged);
            cJSON_AddNumberToObject(dot11vParamBandSteering_6g, "preferred", sp->sp_default->band_steer_6g->steering_btm_params->pref);
            cJSON_AddNumberToObject(dot11vParamBandSteering_6g, "disassociationImminent",sp->sp_default->band_steer_6g->steering_btm_params->disassociation_imminent);
            cJSON_AddNumberToObject(dot11vParamBandSteering_6g, "bssTermination",sp->sp_default->band_steer_6g->steering_btm_params->bss_termination);
            cJSON_AddNumberToObject(dot11vParamBandSteering_6g, "retryCount", sp->sp_default->band_steer_6g->steering_btm_params->retry_count);
            cJSON_AddNumberToObject(dot11vParamBandSteering_6g, "retryInterval", sp->sp_default->band_steer_6g->steering_btm_params->retry_interval);
        }

        cJSON_AddItemToObject(bandSteering6G, "dot11vParamStickyClientSteering", dot11vParamStickyClientSteering_6g);
        if(sp->sp_default->band_steer_6g->sticky_btm_params)
        {
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering_6g, "validityIntervalInTBTT",sp->sp_default->band_steer_6g->sticky_btm_params->valid_interval_tbtt);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering_6g, "abridged", sp->sp_default->band_steer_6g->sticky_btm_params->abridged);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering_6g, "preferred", sp->sp_default->band_steer_6g->sticky_btm_params->pref);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering_6g, "disassociationImminent",sp->sp_default->band_steer_6g->sticky_btm_params->disassociation_imminent);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering_6g, "bssTermination",sp->sp_default->band_steer_6g->sticky_btm_params->bss_termination);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering_6g, "retryCount", sp->sp_default->band_steer_6g->sticky_btm_params->retry_count);
            cJSON_AddNumberToObject(dot11vParamStickyClientSteering_6g, "retryInterval", sp->sp_default->band_steer_6g->sticky_btm_params->retry_interval);
            cJSON_AddBoolToObject(dot11vParamStickyClientSteering_6g, "includeNeighbors",sp->sp_default->band_steer_6g->sticky_btm_params->include_neighbors);
        }

        cJSON_AddItemToObject(bandSteering6G, "gwOnlyOverlay", gwOnlyOverlay_6g);
        if(sp->sp_default->band_steer_6g->for_gw_only)
        {
            cJSON_AddStringToObject(gwOnlyOverlay_6g, "preferred5g", c_get_str_by_key(map_ovsdb_pref_5g_allowed,sp->sp_default->band_steer_6g->for_gw_only->pref_5g));
            if(sp->sp_default->band_steer_6g->for_gw_only->gw_only_6g)
                cJSON_AddStringToObject(gwOnlyOverlay_6g, "preferred6g",c_get_str_by_key(map_ovsdb_pref_5g_allowed,sp->sp_default->band_steer_6g->for_gw_only->gw_only_6g->pref_6g));
            cJSON_AddNumberToObject(gwOnlyOverlay_6g, "lwm", sp->sp_default->band_steer_6g->for_gw_only->lwm);
            if(sp->sp_default->band_steer_6g->for_gw_only->gw_only_6g)
                cJSON_AddNumberToObject(gwOnlyOverlay_6g, "hwm", sp->sp_default->band_steer_6g->for_gw_only->gw_only_6g->hwm);
        }
    }

    cJSON *clientSteering = cJSON_CreateObject();
    cJSON *dot11vParamDirectedSteering = cJSON_CreateObject();
    cJSON *dfs = cJSON_CreateObject();
    // Construct meshsteeringprofiles structure
    cJSON_AddItemToObject(steeringprofiledefaults, "clientSteering", clientSteering);
    cJSON_AddItemToObject(steeringprofiledefaults, "dfs", dfs);

    if(sp->sp_default->client_steering)
    {
        cJSON_AddBoolToObject(clientSteering, "enable",sp->sp_default->client_steering->enable);
        cJSON_AddBoolToObject(clientSteering, "overrideDefault11kv",sp->sp_default->client_steering->override_default_11kv);
        cJSON_AddNumberToObject(clientSteering, "backoffSeconds", sp->sp_default->client_steering->backoff_seconds);
        cJSON_AddNumberToObject(clientSteering, "maxKicksInHour", sp->sp_default->client_steering->max_kicks_in_hour);
        cJSON_AddNumberToObject(clientSteering, "busyThresholdMbps",sp->sp_default->client_steering->busy_threshold_mbps);
        cJSON_AddNumberToObject(clientSteering, "maxPoorThroughputCount", sp->sp_default->client_steering->max_poor_throughput_count);
        cJSON_AddNumberToObject(clientSteering, "throughputChangeMbps", sp->sp_default->client_steering->tp_change_mbps);
        cJSON_AddNumberToObject(clientSteering, "throughputImprovementPct", sp->sp_default->client_steering->tp_improvement_pct);
        cJSON_AddNumberToObject(clientSteering, "throughputChangeMbps2gOnly", sp->sp_default->client_steering->tp_change_mbps_2g_only);
        cJSON_AddNumberToObject(clientSteering, "throughputImprovementPct2gOnly",sp->sp_default->client_steering->tp_improvement_pct_2g_only);
        cJSON_AddNumberToObject(clientSteering, "throughputChangeMbpsDownsteer",sp->sp_default->client_steering->tp_change_mbps_downsteer);
        cJSON_AddNumberToObject(clientSteering, "throughputImprovementPctDownsteer",sp->sp_default->client_steering->tp_improvement_pct_downsteer);
        cJSON_AddNumberToObject(clientSteering, "throughputChangeMbps5gTo6g",sp->sp_default->client_steering->tp_change_mbps_5g_to_6g);
        cJSON_AddNumberToObject(clientSteering, "throughputImprovementPct5gTo6g",sp->sp_default->client_steering->tp_improvement_pct_5g_to_6g);
        cJSON_AddNumberToObject(clientSteering, "throughputChangeMbps6gTo5g", sp->sp_default->client_steering->tp_change_mbps_6g_to_5g);
        cJSON_AddNumberToObject(clientSteering, "throughputImprovementPct6gTo5g",sp->sp_default->client_steering->tp_improvement_pct_6g_to_5g);
        cJSON_AddNumberToObject(clientSteering, "kickReason", sp->sp_default->client_steering->kick_reason);
        cJSON_AddStringToObject(clientSteering, "kickType", c_get_str_by_key(map_ovsdb_kick_type,sp->sp_default->client_steering->kick_type));
        cJSON_AddStringToObject(clientSteering, "specKickType", c_get_str_by_key(map_ovsdb_kick_type,sp->sp_default->client_steering->spec_kick_type));
        cJSON_AddNumberToObject(clientSteering, "lwm",sp->sp_default->client_steering->lwm);
        cJSON_AddNumberToObject(clientSteering, "lwm_6g",sp->sp_default->client_steering->lwm_6g);
        cJSON_AddNumberToObject(clientSteering, "hwm",sp->sp_default->client_steering->hwm);
        cJSON_AddBoolToObject(clientSteering, "authBlock", sp->sp_default->client_steering->auth_block);
        cJSON_AddBoolToObject(clientSteering, "probeBlock",sp->sp_default->client_steering->probe_block);
        cJSON_AddNumberToObject(clientSteering, "authRejectReason",sp->sp_default->client_steering->auth_reject_reason);
        cJSON_AddNumberToObject(clientSteering, "maxRejects",sp->sp_default->client_steering->max_rejects);
        cJSON_AddStringToObject(clientSteering, "rejectDetection", c_get_str_by_key(map_ovsdb_reject_detection,sp->sp_default->client_steering->reject_detection));
        cJSON_AddNumberToObject(clientSteering, "maxRejectsPeriod", sp->sp_default->client_steering->max_rejects_period);
        cJSON_AddNumberToObject(clientSteering, "recoveryPeriod", sp->sp_default->client_steering->recovery_period);
        cJSON_AddNumberToObject(clientSteering, "enforcePeriod", sp->sp_default->client_steering->enforce_period);
        cJSON_AddNumberToObject(clientSteering, "scKickDebouncePeriod", sp->sp_default->client_steering->sc_kick_debounce_period);

        cJSON_AddItemToObject(clientSteering, "dot11vParamDirectedSteering", dot11vParamDirectedSteering);
        if(sp->sp_default->client_steering->kv_params_direct)
        {
            cJSON_AddNumberToObject(dot11vParamDirectedSteering, "validityIntervalInTBTT", sp->sp_default->client_steering->kv_params_direct->valid_interval_tbtt);
            cJSON_AddNumberToObject(dot11vParamDirectedSteering, "abridged", sp->sp_default->client_steering->kv_params_direct->abridged);
            cJSON_AddNumberToObject(dot11vParamDirectedSteering, "preferred", sp->sp_default->client_steering->kv_params_direct->pref);
            cJSON_AddNumberToObject(dot11vParamDirectedSteering, "disassociationImminent", sp->sp_default->client_steering->kv_params_direct->disassociation_imminent);
            cJSON_AddNumberToObject(dot11vParamDirectedSteering, "bssTermination", sp->sp_default->client_steering->kv_params_direct->bss_termination);
            cJSON_AddNumberToObject(dot11vParamDirectedSteering, "retryCount", sp->sp_default->client_steering->kv_params_direct->retry_count);
            cJSON_AddNumberToObject(dot11vParamDirectedSteering, "retryInterval", sp->sp_default->client_steering->kv_params_direct->retry_interval);
        }
    }

    if(sp->sp_default->dfs)
        cJSON_AddBoolToObject(dfs, "supported", sp->sp_default->dfs->is_supported);

    cJSON *devicespecificprofiles = cJSON_CreateArray();
    cJSON_AddItemToObject(meshsteeringprofiles, "devicespecificprofiles", devicespecificprofiles);
    if(sp->device)
    {
        int i;
        for (i = 0; i < sp->device->count; i++)
        {
            cJSON *profile = cJSON_CreateObject();
            cJSON_AddItemToArray(devicespecificprofiles, profile);
            cJSON_AddStringToObject(profile, "description", sp->device->profiles[i].description);
            cJSON_AddNumberToObject(profile, "id", i);
            if(sp->device->profiles[i].present_bandSteering)
                cJSON_AddItemToObject(profile, "bandSteering", create_bandSteering_object(sp->device->profiles[i].bandSteering));
            if(sp->device->profiles[i].present_bandSteering6g)
                cJSON_AddItemToObject(profile, "bandSteering6G", create_bandSteering6G_object(sp->device->profiles[i].bandSteering6g));
            if(sp->device->profiles[i].present_clientSteering)
                cJSON_AddItemToObject(profile, "clientSteering", create_clientSteering_object(sp->device->profiles[i].clientSteering));
        }
    }
    char *string = cJSON_PrintUnformatted(root);

    MeshInfo("%s\n", string);

    FILE *file = fopen(STEERING_CONFIG_FILE, "w");

    if (file == NULL) {
        MeshInfo("%s: Error in opening file: %s\n",__FUNCTION__,STEERING_CONFIG_FILE);
        return;
    }

    // Write the string to the file
    fprintf(file, "%s", string);

    // Close the file
    fclose(file);

    // Free memory
    free(string);
    cJSON_Delete(root);

}

/* See helper.h for details. */
void* blob_data_convert( const void *buf, size_t len, eBlobType blob_type )
{
    int blob_size = 0;
    process_fn_t process = NULL;
    destroy_fn_t destroy = NULL;

    switch(blob_type)
    {
        case MESH:
            blob_size = sizeof(meshbackhauldoc_t);
            process = process_meshbackhauldoc;
            destroy = meshbackhauldoc_destroy;
        break;
        case STEERING_PROFILE_DEFAULT:
            blob_size = sizeof(sp_doc_t);
            process = process_spsteeringdoc;
            destroy = destroy_spsteeringdoc;
        break;
        case DEVICE:
            blob_size = sizeof(dp_doc_t);
            process = process_dpdoc;
            destroy = destroy_dpdoc;
        break;
        case CONFIGS:
            blob_size = sizeof(configs_doc_t);
            process = process_configsdoc;
            destroy = destroy_configsdoc;
        break;
        case INTERFERENCE:
            blob_size = sizeof(ai_doc_t);
            process = process_aidoc;
            destroy = destroy_aidoc;
        break;
        case WIFI_MOTION:
            blob_size = sizeof(wfm_doc_t);
            process = process_wfmdoc;
            destroy = destroy_wfmdoc;
        break;
        case CHANNEL_PLAN_DATA:
            blob_size = sizeof(channel_plan_doc_t);
            process   = process_channelplandoc;
            destroy   = destroy_channelplandoc;
        break;
        default:
        break;
    }
    /*CID 379977 paasing null pointer destroy to helper_convert,which dereferences it.*/
    if(process != NULL && destroy != NULL)
    {
      return helper_convert( buf, len, blob_size, meshBlobNameArr[blob_type].blob_name_str,
                            MSGPACK_OBJECT_ARRAY, true,
                           (process_fn_t) process,
                           (destroy_fn_t) destroy );
    }
    else
    {
        MeshError("Error: process or destroy function is NULL.\n");
        return NULL;
    }
}

/* See helper.h for details. */
void meshbackhauldoc_destroy( void *data )
{
     meshbackhauldoc_t *mb = ( meshbackhauldoc_t *) data;
    if( NULL != mb )
    {
        if( NULL != mb->subdoc_name )
        {
            free( mb->subdoc_name );
        }
        free( mb );
    }
}

/* See webcfgdoc.h for details. */
const char* meshbackhauldoc_strerror( int errnum )
{
    struct error_map {
        int v;
        const char *txt;
    } map[] = {
        { .v = MB_OK,                               .txt = "No errors." },
        { .v = MB_OUT_OF_MEMORY,                    .txt = "Out of memory." },
        { .v = MB_INVALID_FIRST_ELEMENT,            .txt = "Invalid first element." },
        { .v = MB_INVALID_VERSION,                  .txt = "Invalid 'version' value." },
        { .v = MB_INVALID_OBJECT,                .txt = "Invalid 'value' array." },
        { .v = 0, .txt = NULL }
    };
    int i = 0;

    while( (map[i].v != errnum) && (NULL != map[i].txt) ) { i++; }

    if( NULL == map[i].txt )
    {
        //CcspTraceWarning(("----meshbackhauldoc_strerror----\n"));
        return "Unknown error.";
    }

    return map[i].txt;
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

msgpack_object* __finder( const char *name,
                          msgpack_object_type expect_type,
                          msgpack_object_map *map )
{
    uint32_t i;

    if (map == NULL) {
        MeshInfo("map obeject is NULL\n");
        return NULL;
    }
    for( i = 0; i < map->size; i++ )
    {
        if( MSGPACK_OBJECT_STR == map->ptr[i].key.type )
        {
            if( expect_type == map->ptr[i].val.type )
            {
                if( 0 == match(&(map->ptr[i]), name) )
                {
                    return &map->ptr[i].val;
                }
            }
            else if(MSGPACK_OBJECT_STR == map->ptr[i].val.type)
            {
                if(0 == strncmp(map->ptr[i].key.via.str.ptr, name, strlen(name)))
                {
                    return &map->ptr[i].val;
                }

             }
             else
            {
                if(0 == strncmp(map->ptr[i].key.via.str.ptr, name, strlen(name)))
                {
                    return &map->ptr[i].val;
                }

             }
            }
        }
     errno = HELPERS_MISSING_WRAPPER;
    return NULL;
}

/**
 *  Convert the msgpack map into the doc_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_meshdocparams ( meshbackhauldoc_t *mb, msgpack_object_map *mapobj )
{
    int left = mapobj->size;
    uint8_t objects_left = 0x02;
    msgpack_object_kv *p;
    p = mapobj->ptr;
    while( (0 < objects_left) && (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
            {
                if( 0 == match(p, "Enable") )
                {
                    mb->mesh_enable = p->val.via.boolean;
                    objects_left &= ~(1 << 0);
                }
                if( 0 == match(p, "Ethbhaul") )
                {
                    mb->ethernetbackhaul_enable = p->val.via.boolean;
                    objects_left &= ~(1 << 1);
                }
              }
        }
        p++;
    }

    if( 1 & objects_left ) {
    } else {
        errno = MB_OK;
    }

    return (0 == objects_left) ? 0 : -1;
}

int process_meshbackhauldoc(void *data,int num, ... )
{
    va_list valist;
    meshbackhauldoc_t * mb = (meshbackhauldoc_t *)data;

    va_start(valist, num);

    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_map *mapobj = &obj->via.map;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    mb->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    mb->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);
    mb->transaction_id = (uint16_t) obj3->via.u64;

    va_end(valist);
    if (0 != process_meshdocparams( mb,mapobj ))
    {
        return -1;
    }
    return 0;
}

void destroy_wfmdoc( void *data )
{
    wfm_doc_t *wfm = ( wfm_doc_t *) data;
    if( NULL != wfm )
    {
        if( NULL != wfm->subdoc_name )
        {
            free( wfm->subdoc_name );
            wfm->subdoc_name = NULL;
        }
        free( wfm );
        wfm = NULL;
    }
}

int process_wfmdocparams (wfm_doc_t *wfm, msgpack_object_map *mapobj )
{
    int left = mapobj->size;
    msgpack_object_kv *p;
    p = mapobj->ptr;
    while(0 < left--)
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
            {
                if( 0 == match(p, "wfm_enable") )
                {
                    wfm->wfm_enable = p->val.via.boolean;
                }
            }
        }
        p++;
    }
    return 0;
}

int process_wfmdoc(void *data,int num, ... )
{
    va_list valist;
    wfm_doc_t *wfm = (wfm_doc_t *)data;

    va_start(valist, num);

    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_map *mapobj = &obj->via.map;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    wfm->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    wfm->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);
    wfm->transaction_id = (uint16_t) obj3->via.u64;

    va_end(valist);
    if (0 != process_wfmdocparams( wfm,mapobj ))
    {
        return -1;
    }
    return 0;
}

void destroy_channelplandoc(void *data)
{
    channel_plan_doc_t *channel_plan_data = (channel_plan_doc_t *)data;
    if (channel_plan_data != NULL) {
        if (channel_plan_data->subdoc_name) {
            free(channel_plan_data->subdoc_name);
            channel_plan_data->subdoc_name = NULL;
        }
        if (channel_plan_data->keepout_channel_list != NULL) {
            if (channel_plan_data->keepout_channel_list->plan_id != NULL) {
                free(channel_plan_data->keepout_channel_list->plan_id);
                channel_plan_data->keepout_channel_list->plan_id = NULL;
            }
            if (channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_160 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_160);
            if (channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_320 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_320);
            if (channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_80 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_80);
            if (channel_plan_data->keepout_channel_list->config.radio5G.ko_channel_160 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio5G.ko_channel_160);
            if (channel_plan_data->keepout_channel_list->config.radio5G.ko_channel_320 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio5G.ko_channel_320);
            if (channel_plan_data->keepout_channel_list->config.radio5G.ko_channel_80 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio5G.ko_channel_80);
            if (channel_plan_data->keepout_channel_list->config.radio2G.ko_channel_160 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio2G.ko_channel_160);
            if (channel_plan_data->keepout_channel_list->config.radio2G.ko_channel_320 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio2G.ko_channel_320);
            if (channel_plan_data->keepout_channel_list->config.radio2G.ko_channel_80 != NULL)
                free(channel_plan_data->keepout_channel_list->config.radio2G.ko_channel_80);

            free(channel_plan_data->keepout_channel_list);
            channel_plan_data->keepout_channel_list = NULL;
        }
        if (channel_plan_data->HD_recc != NULL) {
            if (channel_plan_data->HD_recc->plan_id != NULL) {
                free(channel_plan_data->HD_recc->plan_id);
                channel_plan_data->HD_recc->plan_id = NULL;
            }
            if (channel_plan_data->HD_recc->radio_config != NULL) {
                free(channel_plan_data->HD_recc->radio_config);
                channel_plan_data->HD_recc->radio_config = NULL;
            }
            free(channel_plan_data->HD_recc);
            channel_plan_data->HD_recc = NULL;
        }
        free(channel_plan_data);
        channel_plan_data = NULL;
    }
}

/*basic channel validator that checks only the boundaries for each radio*/

bool radio_channel_validator (int channel, radio_type_t radio_type) {
     if (radio_type == RADIO_TYPE_6G) {
         if (channel >=1 && channel <= 229) {
             return 1;
         }
     } else if (radio_type == RADIO_TYPE_5G) {
         if (channel >=36 && channel <= 165) {
             return 1;
         }
     } else if (radio_type == RADIO_TYPE_2G) {
         if (channel >=1 && channel <= 11) {
             return 1;
         }
     } 
     return 0;
}

int process_config_radio_params(radio_keepout_channels *radio,msgpack_object_map *map,radio_type_t radio_type)
{
    int left = map->size;
    msgpack_object_kv *p;
    p = map->ptr;
    if (p == NULL) {
        MeshInfo("msgpack_object_map is NULL\n");
        return -1;
    }
    while (0 < left--)
    {
        if (MSGPACK_OBJECT_STR == p->key.type)
        {
            if (MSGPACK_OBJECT_ARRAY == p->val.type)
            {
                uint32_t i;

                if (0 == match(p,"160"))
                {
                    radio->n_ko_channel_160 = p->val.via.array.size;
                    radio->ko_channel_160 = (int *) calloc (radio->n_ko_channel_160,sizeof(int));
                    if (radio->ko_channel_160 == NULL) {
                        MeshInfo("memory allocation failed for radio interface");
                        return -1;
                    }
                    for (i = 0; i < p->val.via.array.size; i++) {
                        if (radio_channel_validator(p->val.via.array.ptr[i].via.u64,radio_type))
                            radio->ko_channel_160[i] = p->val.via.array.ptr[i].via.u64;  
                    }
                }
                if (0 == match(p,"320"))
                {
                    radio->n_ko_channel_320 = p->val.via.array.size;
                    radio->ko_channel_320 = (int *) calloc (radio->n_ko_channel_320,sizeof(int));
                    if (radio->ko_channel_320 == NULL) {
                        MeshInfo("memory allocation failed for radio interface");
                        return -1;
                    }
                    for (i = 0; i < p->val.via.array.size; i++) {
                        if (radio_channel_validator(p->val.via.array.ptr[i].via.u64,radio_type))
                            radio->ko_channel_320[i] = p->val.via.array.ptr[i].via.u64;
                    }
                }
            }
        }
        p++;
    }
    return 0;
}

int prcoess_config_params (channel_keep_out *channel_plan,msgpack_object_map *map)
{
    if (channel_plan == NULL || map == NULL) {
        return -1;
    }
    int left = map->size;
    msgpack_object_kv *p;
    p = map->ptr;
    if (p == NULL) {
        return -1;
    }
    while(0 < left--)
    {
        if (MSGPACK_OBJECT_STR == p->key.type)
        {
            if (MSGPACK_OBJECT_MAP == p->val.type)
            {
                if (0 == match(p, "radio6G"))
                {
                    process_config_radio_params(&channel_plan->config.radio6G,&p->val.via.map,RADIO_TYPE_6G);
                }
                if (0 == match(p, "radio5G"))
                {
                    process_config_radio_params(&channel_plan->config.radio5G,&p->val.via.map,RADIO_TYPE_5G);
                }
                if (0 == match(p, "radio2G"))
                {
                    process_config_radio_params(&channel_plan->config.radio2G,&p->val.via.map,RADIO_TYPE_2G);
                }
            }
        }
        p++;
    }
    return 0;
}

int process_channel_plan_params (channel_keep_out * channel_plan, msgpack_object_map *mapobj)
{
    if (channel_plan== NULL || mapobj == NULL) {
        return -1;
    }
    int left = mapobj->size;
    msgpack_object_kv *p;
    char *val;
    p = mapobj->ptr;
    if (p == NULL) {
        return -1;
    }
    while(0 < left--)
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if (MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type)
            {
                if (0 == match(p, "priority"))
                {
                    channel_plan->priority = p->val.via.u64;
                }
            }
            if (MSGPACK_OBJECT_STR == p->val.type)
            {
                if (0 == match(p, "planId"))
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val) {
                        channel_plan->plan_id = (char *)calloc((p->val.via.str.size),sizeof(char));
                        if (!channel_plan->plan_id) {
                            MeshInfo("Memory allocation failed for plan_id\n");
                            free(val);
                            return -1;
                        }
                        int rc = strcpy_s(channel_plan->plan_id,(p->val.via.str.size+1),val);
                        if (rc != EOK)
                        {
                            ERR_CHK(rc);
                            MeshError("Error in copying\n");
                        }
                        free(val);
                    }
                }
            }
            if (MSGPACK_OBJECT_MAP == p->val.type)
            {
                if (0 == match(p, "config"))
                {
                    if (prcoess_config_params(channel_plan,&p->val.via.map) != 0) 
                        MeshInfo("prcoess_config_params failed \n");
                }
            }
        }
        p++;
    }
    return 0;
}

void fill_channel_bandwidth_and_num(uint8_t *bandwidth,uint16_t *channel,msgpack_object_map *mapobj) {
    if (mapobj == NULL) {
        return ;
    }
    msgpack_object_kv *p;
    p = mapobj->ptr;
    if (p == NULL) {
        return ;
    }
    if (MSGPACK_OBJECT_STR == p->key.type)
    {
        if (MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type)
        {
            *channel = p->val.via.u64;
            if (0 == match(p,"320")) {
                *bandwidth = HT_320;
            } else if (0 == match(p,"160")) {
                *bandwidth = HT_160;
            } else if(0 == match(p,"80")) {
                *bandwidth = HT_80;
            } else if(0 == match(p,"20")) {
                *bandwidth = HT_20;
            } else {
                *bandwidth = HT_UNSUPPORTED;
                MeshError("%s %d Unsupported bandwidth\n", __FUNCTION__, __LINE__);
                return ;
            } 
        }
    }
}

int process_hd_recc_config (radio_channel_config * radio_config,msgpack_object_map *mapobj) {
    if (mapobj == NULL) {
        return -1;
    }
    int left = mapobj->size;
    msgpack_object_kv *p;
    p = mapobj->ptr;
    if (p == NULL) {
        return -1;
    }
    while(0 < left--)
    {
        if (MSGPACK_OBJECT_STR == p->key.type )
        {
            if (MSGPACK_OBJECT_MAP == p->val.type)
            {
                if (0 == match(p,"radio6G")) {
                    fill_channel_bandwidth_and_num(&radio_config->radio6G_bandwidth,&radio_config->radio6G_channel,&p->val.via.map);
                }
                if (0 == match(p,"radio5G")) {
                    fill_channel_bandwidth_and_num(&radio_config->radio5G_bandwidth,&radio_config->radio5G_channel,&p->val.via.map);
                }
                if (0 == match(p,"radio2G")) {
                    fill_channel_bandwidth_and_num(&radio_config->radio2G_bandwidth,&radio_config->radio2G_channel,&p->val.via.map);
                }
            }
        }
    p++;
    }
    return 0;
}

int process_hd_recommendation(HD_recc *HD_recc,msgpack_object_map *mapobj) {
    if (HD_recc == NULL || mapobj == NULL) {
        return -1;
    }
    int left = mapobj->size;
    msgpack_object_kv *p;
    char *val;
    p = mapobj->ptr;
    if (p == NULL) {
        return -1;
    }
    while(0 < left--)
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if (MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type)
            {
                if (0 == match(p, "priority"))
                {
                    HD_recc->priority = p->val.via.u64;
                } else if(0 == match(p, "expiry")){
                    HD_recc->expiry = p->val.via.u64;
                }
            }
            if (MSGPACK_OBJECT_STR == p->val.type)
            {
                if (0 == match(p, "planId"))
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val)
                    {
                        HD_recc->plan_id = (char *)calloc((p->val.via.str.size),sizeof(char));
                        if (!HD_recc->plan_id)
                        {
                            MeshInfo("%s: Memory allocation failed for plan_id\n",__func__);
                            free(val);
                            return -1;
                        }
                        int rc = strcpy_s(HD_recc->plan_id,(p->val.via.str.size+1),val);
                        if (rc != EOK)
                        {
                            ERR_CHK(rc);
                            MeshError("%s : Error in string copying\n",__func__);
                        }
                        free(val);
                    }
                }
            }
            if (MSGPACK_OBJECT_MAP == p->val.type)
            {
                if (0 == match(p,"config"))
                {
                    HD_recc->radio_config = (radio_channel_config *)calloc(1,sizeof(radio_channel_config));
                    if (HD_recc->radio_config == NULL) {
                        MeshError("%s: Memory allocation failed for radio_channel_config\n",__func__);
                        return -1;
                    }
                    if (process_hd_recc_config(HD_recc->radio_config,&p->val.via.map) != 0) {
                        MeshError("%s : Failed to process hd_recc config!\n",__func__);
                    }
                }
            }
        }
    p++;
    }
    return 0;
}

int process_channelplandoc(void *data,int num, ... )
{
    va_list valist;
    msgpack_object_kv *p;
    channel_plan_doc_t *channel_plan_data = (channel_plan_doc_t *)data;

    va_start(valist, num);

    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_map *mapobj = &obj->via.map;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    channel_plan_data->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    channel_plan_data->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);
    channel_plan_data->transaction_id = (uint16_t) obj3->via.u64;

    va_end(valist);

    p = mapobj->ptr;
    if (p == NULL) {
        return -1;
    }
    int left = mapobj->size;
    while( (0 < left--) ) {
        if (MSGPACK_OBJECT_STR == p->key.type) {
            if (MSGPACK_OBJECT_MAP == p->val.type) {
                if (0 == match(p, "channelKeepOut")) {
                    if (p->val.via.map.size > 0) {
                        channel_plan_data->keepout_channel_list = (channel_keep_out *)calloc(1,sizeof(channel_keep_out));
                        if (0 != process_channel_plan_params(channel_plan_data->keepout_channel_list,&p->val.via.map)) {
                            MeshInfo("processing channel_keepout is failed");
                            return -1;
                        }
                    }
                }
                if (0 == match(p,"HDRecc")) {
                    if (p->val.via.map.size > 0) {
                        channel_plan_data->HD_recc = (HD_recc *)calloc(1,sizeof(HD_recc));
                        if (process_hd_recommendation(channel_plan_data->HD_recc,&p->val.via.map) != 0) {
                            MeshError("%s : Failed to process the HD recommendation\n",__func__);
                        }
                    }
                }
            }
        }
        p++;
    }
    return 0;
}

int process_dp_steering_gwonly(DpGwOnlyOverlay *gw,msgpack_object_map *map)
{
    int left = map->size;
    msgpack_object_kv *p;
    p = map->ptr;

    while( (0 < left--))
    {   
        if( MSGPACK_OBJECT_STR == p->key.type )
        {   
            if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                if( 0 == match(p, "lwm") )
                 {
                     gw->lwm = (int) p->val.via.u64;
                 }
            }
        }
        p++;
    }
    return 0;
}

int process_dp_steering_6g_gwonly(DpGwOnlyOverlay6g *gw_6g,msgpack_object_map *map)
{
    int left = map->size;
    msgpack_object_kv *p;
    c_item_t          *item;
    char *val;
    p = map->ptr;

    while( (0 < left--))
    {   
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( 0 == match(p, "preferred6g") )
            {
                val = strndup( p->val.via.str.ptr, p->val.via.str.size );

                if (val == NULL)
                    MeshError("Memory allocation failed for preferred6g value");
                else
                {
                    item = c_get_item_by_str(map_ovsdb_pref_5g_allowed, val);
                    if (item)
                        gw_6g->pref_6g  = (sp_client_pref_allowed)item->key;
                    else
                        MeshError("Unknown preferred 6g %s",val);
                    free(val);
                }
            }
        }
        p++;
    }
    return 0;
}

int process_dp_bandsteering(DpBandSteering_t *dp_steer, msgpack_object_map *map)
{
    int left = map->size;
    msgpack_object_kv *p;
    c_item_t          *item;
    char *val;

    MeshInfo("process_dp_bandsteering : size = %d\n",left);
    p = map->ptr;
    while((0 < left--) )
    {   
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
            {
                 if( 0 == match(p, "preAssociationAuthBlock") )
                 {
                     dp_steer->present_preAssociationAuthBlock = true;
                     dp_steer->preAssociationAuthBlock = p->val.via.boolean;
                 }
                 if( 0 == match(p, "enable") )
                 {
                     dp_steer->present_enable = true;
                     dp_steer->enable = p->val.via.boolean;
                 }
                 if( 0 == match(p, "kickUponIdleOnly") )
                 {
                     dp_steer->present_kickUponIdleOnly = true;
                     dp_steer->kickUponIdleOnly = p->val.via.boolean;
                 }

            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                 if( 0 == match(p, "hwm") )
                 {
                     dp_steer->present_hwm = true;
                     dp_steer->hwm = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "lwm") )
                 {
                     dp_steer->present_lwm = true;
                     dp_steer->lwm = (int) p->val.via.u64;
                 }
                 else
                     MeshError("process_bs_11kv_params failed\n");
            }
            else if(MSGPACK_OBJECT_STR == p->val.type)
            {   
                if( 0 == match(p, "kickType") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val == NULL)
                        MeshError("Memory allocation failed for kickType value");
                    else
                    {
                        item = c_get_item_by_str(map_ovsdb_kick_type, val);
                        if (item)
                        {
                           dp_steer->present_kickType = true;
                           dp_steer->kickType  = (sp_client_kick_t)item->key;
                        }
                        else
                            MeshError("Unknown kick type %s",val);
                        free(val);
                    }
                }
                if( 0 == match(p, "stickyKickType") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val == NULL)
                        MeshError("Memory allocation failed for stickyKickType value");
                    else
                    {
                        item = c_get_item_by_str(map_ovsdb_kick_type, val);
                        if (item)
                        {
                            dp_steer->present_stickyKickType = true;
                            dp_steer->stickyKickType  = (sp_client_kick_t)item->key;
                        }
                        else
                            MeshError("Unknown kick type %s",val);
                        free(val);
                    }
                }
            }
            else if( MSGPACK_OBJECT_MAP  == p->val.type )
            {   
                if( 0 == match(p, "gwOnlyOverlay"))
                {
                    dp_steer->gwOnly = malloc( sizeof(DpGwOnlyOverlay));
                    memset(dp_steer->gwOnly, 0, sizeof(DpGwOnlyOverlay));
                    dp_steer->present_gwOnly = true;
                    process_dp_steering_gwonly(dp_steer->gwOnly, &p->val.via.map);
                }
            }
            else
                MeshError("process_dp_bandsteering invalid type\n");
        p++;
        }
    }
    return 0;
}

int process_dp_bandsteering6g(DpBandSteering6G_t *dp_steer6g, msgpack_object_map *map)
{
    int left = map->size;
    msgpack_object_kv *p;
    c_item_t          *item;
    char *val;
    MeshInfo("process_dp_bandsteering6g size = %d\n",left);
    p = map->ptr;
    while((0 < left--) )
    {   
        if( MSGPACK_OBJECT_STR == p->key.type )
        {   
            if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                 if( 0 == match(p, "maxRejects") )
                 {
                     dp_steer6g->present_maxRejects = true;
                     dp_steer6g->maxRejects = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "hwm") )
                 {
                     dp_steer6g->present_hwm = true;
                     dp_steer6g->hwm = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "hwm2") )
                 {
                     dp_steer6g->present_hwm2 = true;
                     dp_steer6g->hwm2 = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "hwm3") )
                 {
                     dp_steer6g->present_hwm3 = true;
                     dp_steer6g->hwm3 = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "lwm") )
                 {
                     dp_steer6g->present_lwm = true;
                     dp_steer6g->lwm = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "lwm2") )
                 {
                     dp_steer6g->present_lwm2 = true;
                     dp_steer6g->lwm2 = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "lwm3") )
                 {
                     dp_steer6g->present_lwm3 = true;
                     dp_steer6g->lwm3 = (int) p->val.via.u64;
                 }
                 else
                     MeshError("process_bs_11kv_params failed\n");
            }
            else if(MSGPACK_OBJECT_STR == p->val.type)
            {
                if( 0 == match(p, "kickType") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val == NULL)
                        MeshError("Memory allocation failed for kickType value");
                    else
                    {
                        item = c_get_item_by_str(map_ovsdb_kick_type, val);
                        if (item)
                        {
                            dp_steer6g->present_kickType = true;
                            dp_steer6g->kickType  = (sp_client_kick_t)item->key;
                        }
                        else
                            MeshError("Unknown preferred kickType %s",val);
                        free(val);
                    }
                }
                if( 0 == match(p, "stickyKickType") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val == NULL)
                        MeshError("Memory allocation failed for stickyKickType value");
                    else
                    {
                        item = c_get_item_by_str(map_ovsdb_kick_type, val);
                        if (item)
                        {
                            dp_steer6g->present_stickyKickType = true;
                            dp_steer6g->stickyKickType  = (sp_client_kick_t)item->key;
                        }
                        else
                            MeshError("Unknown stickyKickType %s",val);
                        free(val);
                    }
                }
                if( 0 == match(p, "preferred5g") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );

                    if (val == NULL)
                        MeshError("Memory allocation failed for preferred5g value");
                    else
                    {
                        item = c_get_item_by_str(map_ovsdb_pref_5g_allowed, val);
                        if (item)
                        {
                            dp_steer6g->present_pref_5g  = true;
                            dp_steer6g->pref_5g  = (sp_client_pref_allowed)item->key;
                        }
                        else
                            MeshError("Unknown preferred 5g %s",val);
                        free(val);
                    }
                 }
                 else if( 0 == match(p, "preferred6g") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );

                     if (val == NULL)
                        MeshError("Memory allocation failed for preferred6g value");
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_pref_5g_allowed, val);
                         if (item)
                         {
                             dp_steer6g->present_pref_6g  = true;
                             dp_steer6g->pref_6g  = (sp_client_pref_allowed)item->key;
                         }
                         else
                             MeshError("Unknown preferred 6g %s",val);
                         free(val);
                     }
                 }
            }
            else if( MSGPACK_OBJECT_MAP  == p->val.type )
            {
                if( 0 == match(p, "gwOnlyOverlay"))
                {
                    dp_steer6g->gw_only_6g = malloc( sizeof(DpGwOnlyOverlay6g));
                    memset(dp_steer6g->gw_only_6g, 0, sizeof(DpGwOnlyOverlay6g));
                    dp_steer6g->present_gw_only_6g = true;
                    process_dp_steering_6g_gwonly(dp_steer6g->gw_only_6g, &p->val.via.map);
                }
            }
            else
                MeshError("process_dp_bandsteering6g :  invalid type\n");
        p++;
        }
    }
    return 0;
}



int process_dp_client(DpClientSteering_t *dp_client, msgpack_object_map *map)
{
    int left = map->size;
    msgpack_object_kv *p;
    c_item_t          *item;
    char *val;

    p = map->ptr;
    MeshInfo("process_dp_client : size = %d\n",left);
    while((0 < left--) )
    {   
        if( MSGPACK_OBJECT_STR == p->key.type )
        {   
            if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
            {
                 if( 0 == match(p, "overrideDefault11kv") )
                 {
                     dp_client->present_overrideDefault11kv = true;
                     dp_client->overrideDefault11kv = p->val.via.boolean;
                 }
                 if( 0 == match(p, "enable") )
                 {
                     dp_client->present_enable = true;
                     dp_client->enable = p->val.via.boolean;
                 }
            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                if( 0 == match(p, "retryTimeoutHours") )
                {
                    dp_client->present_retryTimeoutHours = true;
                    dp_client->retryTimeoutHours = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "busyOverrideThroughputMbps") )
                {
                    dp_client->present_busyOverrideThroughputMbps = true;
                    dp_client->busyOverrideThroughputMbps = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "busyOverrideProbeSnr") )
                {
                    dp_client->present_busyOverrideProbeSnr = true;
                    dp_client->busyOverrideProbeSnr = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "busyPpdusPerMinute"))
                {
                    dp_client->present_busyPpdusPerMinute = true;
                    dp_client->busyPpdusPerMinute = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "nss5GCap") )
                {
                    dp_client->present_nss5GCap = true;
                    dp_client->nss5GCap = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "nss24GCap") )
                {
                    dp_client->present_nss24GCap = true;
                    dp_client->nss24GCap = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "enforcePeriod") )
                {
                    dp_client->present_enforcePeriod = true;
                    dp_client->enforcePeriod = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "maxRejects") )
                {
                    dp_client->present_maxRejects = true;
                    dp_client->maxRejects = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "hwm3") )
                {
                    dp_client->present_hwm3 = true;
                    dp_client->hwm3 = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "hwm2") )
                {
                    dp_client->present_hwm2 = true;
                    dp_client->hwm2 = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "lwm3") )
                {
                    dp_client->present_lwm3 = true;
                    dp_client->lwm3 = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "lwm2") )
                {
                    dp_client->present_lwm2 = true;
                    dp_client->lwm2 = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "maxPoorThroughputCount") )
                {
                    dp_client->present_maxPoorThroughputCount = true;
                    dp_client->maxPoorThroughputCount = (int) p->val.via.u64;
                }
                else if( 0 == match(p, "retryTimeoutHours") )
                {
                    dp_client->present_retryTimeoutHours = true;
                    dp_client->retryTimeoutHours = (int) p->val.via.u64;
                }
                else
                    MeshError("process_bs_11kv_params failed\n");
            }
            else if(MSGPACK_OBJECT_STR == p->val.type)
            {
                if( 0 == match(p, "kickType") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val == NULL)
                        MeshError("Memory allocation failed for kickType value");
                    else
                    {
                        item = c_get_item_by_str(map_ovsdb_kick_type, val);
                        if (item) 
                        {
                            dp_client->present_kickType = true;
                            dp_client->kickType  = (sp_client_kick_t)item->key;
                        }
                        else
                            MeshError("Unknown kick type %s",val);
                        free(val);
                    }
                }
                if( 0 == match(p, "specKickType") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val == NULL)
                        MeshError("Memory allocation failed for specKickType value");
                    else
                    {
                        item = c_get_item_by_str(map_ovsdb_kick_type, val);
                        if (item)
                        {
                            dp_client->present_specKickType = true;
                            dp_client->specKickType  = (sp_client_kick_t)item->key;
                        }
                        else
                            MeshError("Unknown specKickType %s",val);
                        free(val);
                    }
                }
            }
            else
                MeshError("process_dp_client invalid type\n");
        p++;
        }
    }
    return 0;
}

int process_ai(interference_t *i, msgpack_object_map *map )
{
    int left = map->size;
    char              *val;
    c_item_t          *item;

    msgpack_object_kv *p;
    MeshInfo("Number of ai parameters = %d\n",left);
    p = map->ptr;
    while( 0 < left--)
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
           if( MSGPACK_OBJECT_STR == p->val.type )
           {
               if( 0 == match(p, "radio_type") )
               {
                   val = strndup( p->val.via.str.ptr, p->val.via.str.size);
                   if(val == NULL){
                       MeshError("Memory allocation failed for radio_type value");
                   } else {
                       item = c_get_item_by_str(map_ovsdb_radio_type, val);
                       if (item) {
                           i->radio_type = (radio_type_t)item->key;
                       } else {
                           MeshError("Unknown radio type %s",val);
                       }
                       free(val);
                   }
               }

               if( 0 == match(p, "tot_active_if_min") )
               {
                   val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                   if(val) {
                       i->tot_active_interf_min = atof(val);
                       free(val);
                   }
               }

               if( 0 == match(p, "tot_idle_if_min") )
               {
                   val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                   if(val) {
                       i->tot_idle_interf_min = atof(val);
                       free(val);
                   }
               }

               if( 0 == match(p, "avg_active_if") )
               {
                   val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                   if(val) {
                       i->avg_active_interf = atof(val);
                       free(val);
                   }
               }

               if( 0 == match(p, "avg_idle_if") )
               {
                   val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                   if(val) {
                       i->avg_idle_interf = atof(val);
                       free(val);
                   }
               }
            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                if( 0 == match(p, "channel") )
                {
                    i->channel = (int) p->val.via.u64;
                    MeshInfo("interferencee: channel = %d\n",i->channel);
                }
            }
        }
        p++;
    }
    return 0;
}


int process_configs (configs_t *c, msgpack_object_map *map )
{
    int left = map->size;
    char              *val;
    c_item_t          *item;
    msgpack_object_kv *p;
    MeshInfo("Number of configs = %d\n",left);
    p = map->ptr;
    while( 0 < left--)
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( MSGPACK_OBJECT_STR == p->val.type )
            {
                if( 0 == match(p, "name") )
                {
                    c->name = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    MeshInfo("Configs: name = %s\n",c->name);
                }
                if( 0 == match(p, "type") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val == NULL)
                        MeshError("Memory allocation failed for type value");
                    else
                    {
                        item = c_get_item_by_str(map_mwo_configs_type, val);
                        if (item)
                            c->type = (eValueType)item->key;
                        else
                            MeshError("Unknown type %s\n",val);
                        free(val);
                    }
                }
                if( 0 == match(p, "data") )
                {
                    c->value.string_value = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    MeshInfo("Configs: value = %s\n",c->value.string_value);
                }
            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                if( 0 == match(p, "value") )
                 {
                     c->value.int_value = (int) p->val.via.u64;
                     MeshInfo("DeviceProfile: prof_id = %d\n",c->value.int_value);
                 }
            }
            else if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
            {
                if( 0 == match(p, "value") )
                {
                    c->value.boolean_value = p->val.via.boolean;
                }
            }
        }
        p++;
    }
    return 0;
}

int process_client_profile(clients_t *e, msgpack_object_map *map )
{
    int left = map->size;
    char              *val;
    errno_t rc = -1;
    msgpack_object_kv *p;
    MeshInfo("Number of process_client_profile = %d\n",left);
    p = map->ptr;
    while( 0 < left--)
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( MSGPACK_OBJECT_STR == p->val.type )
            {
                if( 0 == match(p, "mac_addr") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if(val)
                    {
                        rc = strcpy_s(e->mac,sizeof(e->mac) , val);
                        if(rc != EOK)
                        {
                            ERR_CHK(rc);
                            MeshError("Error in copying\n");
                        }
                        MeshInfo("DeviceProfile: mac_addr = %s\n",e->mac);
                        free(val);
                    }
                }
            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {   
                if( 0 == match(p, "prof_id") )
                 {   
                     e->id = (int) p->val.via.u64;
                      MeshInfo("DeviceProfile: prof_id = %d\n",e->id);
                 }
            }
        }
        p++;
    }
    return 0;
}


int process_device_profiles( DeviceSpecificProfile_t *e, msgpack_object_map *map )
{
    int left = map->size;
    char              *val;
    errno_t rc = -1;
    msgpack_object_kv *p;
    MeshInfo("No of process_device_profiles = %d\n",left);
    p = map->ptr;
    while( 0 < left--)
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( MSGPACK_OBJECT_STR == p->val.type )
            {
                if( 0 == match(p, "description") )
                {
                    val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                    if (val)
                    {
                        rc = strcpy_s(e->description, 100, val);
                        if(rc != EOK)
                        {
                            ERR_CHK(rc);
                            MeshError("Error in copying\n");
                        }
                        free(val);
                        MeshInfo("Description =%s\n",e->description);
                    }
                }
            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                if( 0 == match(p, "id") )
                 {
                     e->id = (int) p->val.via.u64;
                     MeshInfo("Id: %d\n",e->id);
                 }
            }
            else if( MSGPACK_OBJECT_MAP  == p->val.type )
            {   
                if( 0 == match(p, "clientSteering"))
                {
                    e->clientSteering = malloc( sizeof(DpClientSteering_t));
                    memset( e->clientSteering, 0, sizeof(DpClientSteering_t));
                    e->present_clientSteering = true;
                    process_dp_client(e->clientSteering, &p->val.via.map);
                }
                if( 0 == match(p, "bandSteering6G"))
                {
                    e->bandSteering6g = malloc( sizeof(DpBandSteering6G_t));
                    memset(e->bandSteering6g, 0, sizeof(DpBandSteering6G_t));
                    e->present_bandSteering6g = true;
                    process_dp_bandsteering6g(e->bandSteering6g, &p->val.via.map);
                }
                if( 0 == match(p, "bandSteering"))
                {
                    e->bandSteering =  malloc( sizeof(DpBandSteering_t));
                    memset( e->bandSteering, 0, sizeof(DpBandSteering_t));
                    e->present_bandSteering = true;
                    process_dp_bandsteering(e->bandSteering, &p->val.via.map);
                }
            }

        }
        p++;
    }
    return 0;
}

c_item_t *
_c_get_item_by_key(c_item_t *list, int list_sz, int key)
{
    c_item_t    *item;
    int         i;

    for (item = list,i = 0;i < list_sz; item++, i++) {
        if ((int)(item->key) == key) {
            return item;
        }
    }

    return NULL;
}

char *
_c_get_str_by_key(c_item_t *list, int list_sz, int key)
{
    c_item_t    *item = _c_get_item_by_key(list, list_sz, key);

    if (!item) {
        return "";
    }   

    return (char *)(item->data);
}

c_item_t *
_c_get_item_by_str(c_item_t *list, int list_sz, const char *str)
{
    c_item_t    *item;
    int         i;

    for (item = list,i = 0;i < list_sz; item++, i++) {
        if (strcmp((char *)(item->data), str) == 0) {
            return item;
        }
    }

    return NULL;
}

int process_bs_gw_only_params(sp_gw_only_t *gw,msgpack_object_map *map,bool is_6g)
{
    int left = map->size;
    c_item_t          *item;
    char              *val;
    msgpack_object_kv *p;
    p = map->ptr;
    int objects_left;

    if(is_6g)
    {
        objects_left = 4;
        gw->gw_only_6g = malloc(sizeof(sp_gw_only_6g_t));
        memset(gw->gw_only_6g, 0, sizeof(sp_gw_only_6g_t));
    }
    else
    {
        objects_left = 2;
        gw->gw_only_6g = NULL;
    }

    while( (0 < objects_left) && (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if(MSGPACK_OBJECT_STR == p->val.type)
            {
                 if( 0 == match(p, "preferred5g") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL)
                         MeshError("Memory allocation failed for preferred5g value");
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_pref_5g_allowed, val);
                         if (item)
                             gw->pref_5g  = (sp_client_pref_allowed)item->key;
                         else
                             MeshError("Unknown preferred 5g %s",val);
                         free(val);
                     }
                 }
                 else if( 0 == match(p, "preferred6g") )
                 {          
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL)
                         MeshError("Memory allocation failed for preferred6g value"); 
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_pref_5g_allowed, val);
                         if (item) {
                             if(gw->gw_only_6g)
                                 gw->gw_only_6g->pref_6g  = (sp_client_pref_allowed)item->key;
                         }
                         else
                             MeshError("Unknown preferred 6g %s",val);
                         free(val);
                     }
                }
            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                if( 0 == match(p, "lwm") )
                 {
                     gw->lwm = (int) p->val.via.u64;
                 }
                if( 0 == match(p, "hwm") )
                 {
                     if(gw->gw_only_6g)
                         gw->gw_only_6g->hwm = (int) p->val.via.u64;
                 }
            }
        }
        --objects_left;
        p++;
    }
    return (0 == objects_left) ? 0 : -1;
}

int process_bs_11kv_params(sp_btm_params_t *bs,msgpack_object_map *map, int count)
{
    int left = map->size;
    msgpack_object_kv *p;
    p = map->ptr;
    int objects_left = count;
    while( (0 < objects_left) && (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
            if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
            {      
                 if( 0 == match(p, "includeNeighbors") )
                 {
                     bs->include_neighbors = p->val.via.boolean;
                 }
            }
            else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
            {
                if( 0 == match(p, "validityIntervalInTBTT") )
                 {
                     bs->valid_interval_tbtt = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "abridged") )
                 {
                     bs->abridged = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "preferred") )
                 {
                     bs->pref = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "disassociationImminent") )
                 {
                     bs->disassociation_imminent = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "bssTermination") )
                 {
                     bs->bss_termination = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "retryCount") )
                 {
                     bs->retry_count = (int) p->val.via.u64;
                 }
                 else if( 0 == match(p, "retryInterval") )
                 {
                     bs->retry_interval = (int) p->val.via.u64;
                 }
                 else
                     MeshError("process_bs_11kv_params failed\n");
            }
            else
                MeshError("process_bs_11kv_params invalid type\n");
        --objects_left;
        p++;
        }
    }
    return (0 == objects_left) ? 0 : -1;
}
/**
 *  Convert the msgpack map into the sp_band_steering_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_dfs_params( sp_defaultdoc_t *steer, msgpack_object_map *map)
{
    int left = map->size;
    int objects_left = 1;
    msgpack_object_kv *p;
    sp_dfs_t *e;
    e = steer->dfs;
    p = map->ptr;
    while( (0 < objects_left) && (0 < left--) )
    {   
        if( MSGPACK_OBJECT_STR == p->key.type )
        {

              if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
              {  
                 if( 0 == match(p, "supported") )
                 {   
                     e->is_supported = p->val.via.boolean;
                 }
             }
       }
        --objects_left;
        p++;
    }
    return (0 == objects_left) ? 0 : -1;
}

/**
 *  Convert the msgpack map into the sp_band_steering_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_csparams( sp_defaultdoc_t *steer, msgpack_object_map *map)
{
    int left = map->size;
    c_item_t                *item;
    char              *val;
    int objects_left = 32;
    msgpack_object_kv *p;
    sp_client_steering_t *e;
    e = steer->client_steering;
    p = map->ptr;
    while( (0 < objects_left) && (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {

              if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
              {
                 if( 0 == match(p, "enable") )
                 {
                     e->enable = p->val.via.boolean;
                 }
                 if( 0 == match(p, "overrideDefault11kv") )
                 {
                     e->override_default_11kv = p->val.via.boolean;
                 }
                 if( 0 == match(p, "authBlock") )
                 {
                     e->auth_block = p->val.via.boolean;
                 }
                 if( 0 == match(p, "probeBlock") )
                 {
                     e->probe_block = p->val.via.boolean;
                 }
              }
              else if(MSGPACK_OBJECT_STR == p->val.type)
              {
                 if( 0 == match(p, "kickType") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL) {
                         MeshError("Memory allocation failed for kickType value");
                     }
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_kick_type, val);
                         if (item) {
                             e->kick_type  = (sp_client_kick_t)item->key;
                         }
                         else {
                             MeshError("Unknown kick type %s",val);
                         }
                         free(val);
                     }
                 }
                 if( 0 == match(p, "specKickType") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL) {
                         MeshError("Memory allocation failed for specKickType value");
                     }
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_kick_type, val);
                         if(item) {
                             e->spec_kick_type  = (sp_client_kick_t)item->key;
                         }
                         else {
                             MeshError("Unknown kick type %s",val);
                         }
                         free(val);
                     }
                 }
                 if( 0 == match(p, "rejectDetection") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL) {
                         MeshError("Memory allocation failed for rejectDetection value");
                     }
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_reject_detection, val);
                         if (item) {
                             e->reject_detection = (sp_client_reject_t)item->key;
                         }
                         else {
                             MeshError("Unknown reject detection %s",val);
                         }
                         free(val);
                     }
                 }
              }
              else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
              {  
                 if( 0 == match(p, "backoffSeconds") )
                 {
                     e->backoff_seconds = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "maxKicksInHour") )
                 {   
                     e->max_kicks_in_hour = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "maxPoorThroughputCount") )
                 {   
                     e->max_poor_throughput_count = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "throughputImprovementPct") )
                 {   
                     e->tp_improvement_pct = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "throughputImprovementPct2gOnly") )
                 {   
                     e->tp_improvement_pct_2g_only = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "throughputImprovementPctDownsteer") )
                 {   
                     e->tp_improvement_pct_downsteer = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "throughputImprovementPct5gTo6g") )
                 {   
                     e->tp_improvement_pct_5g_to_6g = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "throughputImprovementPct6gTo5g") )
                 {   
                     e->tp_improvement_pct_6g_to_5g = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "kickReason") )
                 {   
                     e->kick_reason = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "lwm") )
                 {   
                     e->lwm = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "lwm_6g") )
                 {   
                     e->lwm_6g = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "hwm") )
                 {   
                     e->hwm = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "authRejectReason") )
                 {   
                     e->auth_reject_reason = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "maxRejects") )
                 {   
                     e->max_rejects = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "maxRejectsPeriod") )
                 {   
                     e->max_rejects_period = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "recoveryPeriod") )
                 {
                     e->recovery_period = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "enforcePeriod") )
                 {   
                     e->enforce_period = (int) p->val.via.u64;
                     MeshInfo("e->enforce_period :%d\n",e->enforce_period);
                 }
                 if( 0 == match(p, "scKickDebouncePeriod") )
                 {   
                     e->sc_kick_debounce_period = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "busyThresholdMbps") )
                 {
                     e->busy_threshold_mbps = p->val.via.u64;
                 }
                 if( 0 == match(p, "throughputChangeMbps") )
                 {
                     e->tp_change_mbps = p->val.via.f64;
                 }
                 if( 0 == match(p, "throughputChangeMbps2gOnly") )
                 {
                     e->tp_change_mbps_2g_only = p->val.via.f64;
                 }
                 if( 0 == match(p, "throughputChangeMbpsDownsteer") )
                 {
                     e->tp_change_mbps_downsteer = p->val.via.f64;
                 }
                 if( 0 == match(p, "throughputChangeMbps5gTo6g") )
                 {
                     e->tp_change_mbps_5g_to_6g = p->val.via.f64;
                 }
              }
              else if( MSGPACK_OBJECT_MAP  == p->val.type )
              {
                  if( 0 == match(p, "dot11vParamDirectedSteering") )
                  {
                      e->kv_params_direct = malloc( sizeof(sp_btm_params_t));
                      memset(e->kv_params_direct, 0, sizeof(sp_btm_params_t));
                      if( 0 != process_bs_11kv_params(e->kv_params_direct,&p->val.via.map, 7))
                      {
                          MeshInfo(("dot11vParamDirectedSteering failed\n"));
                          return -1;
                      }
                  }
             }
         }
        --objects_left;
        p++;
    }
    return (0 == objects_left) ? 0 : -1;
}

/**
 *  Convert the msgpack map into the sp_band_steering_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_bsdefaultprofile( sp_defaultdoc_t *sp_default, msgpack_object_map *map)
{
    int left = map->size;
    msgpack_object_kv *p;

    p = map->ptr;
    sp_default->band_steer = malloc( sizeof(sp_band_steering_t));
    memset(sp_default->band_steer, 0, sizeof(sp_band_steering_t));
    sp_default->band_steer_6g = malloc( sizeof(sp_band_steering_t));
    memset(sp_default->band_steer_6g, 0, sizeof(sp_band_steering_t));
    sp_default->client_steering = malloc(sizeof(sp_client_steering_t));
    memset(sp_default->client_steering, 0, sizeof(sp_client_steering_t));
    sp_default->dfs = malloc(sizeof(sp_dfs_t));
    memset(sp_default->dfs, 0, sizeof(sp_dfs_t));

    while( (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {   
            if( MSGPACK_OBJECT_MAP == p->val.type )
            {
                if( 0 == match(p, "bandSteering"))
                {
                    if( 0 != process_bsparams(sp_default,&p->val.via.map,false))
                    {   
                        MeshInfo(("process_band steering failed\n"));
                        //return -1;
                    }
                }
                else if( 0 == match(p, "bandSteering6G"))
                {
                    if( 0 != process_bsparams(sp_default,&p->val.via.map,true))
                    {     
                        MeshInfo(("process_band steering 6g failed\n"));
                        return -1;
                    }
                }
                else if( 0 == match(p, "clientSteering"))
                {
                    if( 0 != process_csparams(sp_default,&p->val.via.map))
                    {     
                        MeshInfo(("process_band clientSteering failed\n"));
                        return -1;
                    }
                }
                else if( 0 == match(p, "dfs"))
                {
                    if( 0 != process_dfs_params(sp_default,&p->val.via.map))
                    {   
                        MeshInfo(("process_band dfs failed\n"));
                        return -1;
                    }
                }
            }
        }
        p++;
    }
    return 0;
}

/**
 *  Convert the msgpack map into the sp_band_steering_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_bsparams( sp_defaultdoc_t *steer, msgpack_object_map *map, bool is_6g )
{
    int left = map->size;
    c_item_t                *item;
    char              *val;
    int objects_left;
    msgpack_object_kv *p;
    sp_band_steering_t *e;

    if(is_6g)
    {
        objects_left = 34;
        e = steer->band_steer_6g;
        e->band_steering_6g = malloc(sizeof(sp_band_steering_6g_t));
        memset(e->band_steering_6g, 0, sizeof(sp_band_steering_6g_t));
    }
    else
    {
        objects_left = 29;
        e = steer->band_steer;
        e->band_steering_6g = NULL;
    }
    p = map->ptr;
    while( (0 < objects_left) && (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
              
              if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
              {
                 if( 0 == match(p, "enable") )
                 {
                     e->enable = p->val.via.boolean;
                 }
                 if( 0 == match(p, "steerDuringBackoff") )
                 {
                     e->steer_during_backoff = p->val.via.boolean;
                 }
                 if( 0 == match(p, "preAssociationAuthBlock") )
                 {
                     e->pre_assoc_auth_block = p->val.via.boolean;
                 }
                 if( 0 == match(p, "kickUponIdleOnly") )
                 {
                     e->kick_upon_idle = p->val.via.boolean;
                 }
                 if( 0 == match(p, "neighborListFilterByBeaconReport") )
                 {
                     e->neighbor_list_filter_by_beacon_report = p->val.via.boolean;
                 }
                 if( 0 == match(p, "neighborListFilterByBTMStatus") )
                 {
                     e->neighborListFilterByBTMStatus = p->val.via.boolean;
                 }
                 if( 0 == match(p, "steerDuringBackoff") )
                 {
                     if(e->band_steering_6g)
                         e->band_steering_6g->steerDuringBackoff = (int) p->val.via.boolean;
                 }

              }
              else if(MSGPACK_OBJECT_STR == p->val.type)
              {
                 if( 0 == match(p, "kickType") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL)
                         MeshError("Memory allocation failed for kickType value");
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_kick_type, val);
                         if (item)
                             e->kick_type  = (sp_client_kick_t)item->key;
                         else
                             MeshError("Unknown kick type %s",val);
                         free(val);
                     }
                 }
                 if( 0 == match(p, "stickyKickType") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL)
                         MeshError("Memory allocation failed for stickyKickType value");
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_kick_type, val);
                         if (item)
                             e->sticky_kick_type  = (sp_client_kick_t)item->key;
                         else
                             MeshError("Unknown sticky kick type %s",val);
                         free(val);
                     }
                 }
                 if( 0 == match(p, "preferred5g") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL)
                         MeshError("Memory allocation failed for stickyKickType value");
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_pref_5g_allowed, val);
                         if (item)
                             e->pref_allowed  = (sp_client_pref_allowed)item->key;
                         else
                             MeshError("Unknown preferred 5g %s",val);
                         free(val);
                     }
                 }
                 if( 0 == match(p, "preferred6g") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL)
                         MeshError("Memory allocation failed for preferred6g value");
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_pref_5g_allowed, val);
                         if (item)
                             e->pref_6g = (sp_client_pref_allowed)item->key;
                         else
                             MeshError("Unknown preferred 6g %s",val);
                         free(val);
                     }
                 }

                 if( 0 == match(p, "rejectDetection") )
                 {
                     val = strndup( p->val.via.str.ptr, p->val.via.str.size );
                     if(val == NULL)
                         MeshError("Memory allocation failed for rejectDetection value");
                     else
                     {
                         item = c_get_item_by_str(map_ovsdb_reject_detection, val);
                         if (item)
                             e->reject_detection = (sp_client_reject_t)item->key;
                         else
                             MeshError("Unknown reject detection %s",val);
                         free(val);
                     }
                 }
              }
              else if( MSGPACK_OBJECT_POSITIVE_INTEGER == p->val.type )
              {
                 if( 0 == match(p, "hwm") )
                 {
                     e->hwm = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "hwm2") )
                 {
                     if(e->band_steering_6g)
                         e->band_steering_6g->hwm2 = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "hwm3") )
                 {
                     if(e->band_steering_6g)
                         e->band_steering_6g->hwm3 = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "lwm2") )
                 {
                     if(e->band_steering_6g)
                         e->band_steering_6g->lwm2 = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "lwm3") )
                 {
                     if(e->band_steering_6g)
                         e->band_steering_6g->lwm3 = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "kickReason") )
                 {
                     e->kick_reason = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "stickyKickReason") )
                 {
                     e->sticky_kick_reason = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "lwm") )
                 {
                     e->lwm = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "bottomLwm") )
                 {
                     e->bottomLwm = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "kickDebouncePeriod") )
                 {
                     e->kick_debounce_period = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "stickyKickDebouncePeriod") )
                 {
                     e->sticky_kick_debounce_period = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "backoffSeconds") )
                 {
                     e->backoff_second = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "backoffExpBase") )
                 {
                     e->backoff_exp_base = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "stickyKickGuardTime") )
                 {
                     e->sticky_kick_guard_time = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "stickyKickBackoffTime") )
                 {
                     e->sticky_kick_backoff_time = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "maxRejects") )
                 {
                     e->max_rejects = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "rejectsTimeoutSeconds") )
                 {
                     e->max_rejects_period = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "btmMaxNeighbors") )
                 {
                     e->btmMaxNeighbors = (int) p->val.via.u64;
                 }
                 if( 0 == match(p, "btmMaxNeighbors6g") )
                 {
                     e->btmMaxNeighbors6g = (int) p->val.via.u64;
                 }
              }
              else if( MSGPACK_OBJECT_MAP  == p->val.type )
              {
                  if( 0 == match(p, "dot11vParamBandSteering") )
                  {
                      e->steering_btm_params = malloc( sizeof(sp_btm_params_t));
                      memset(e->steering_btm_params, 0, sizeof(sp_btm_params_t));
                      if( 0 != process_bs_11kv_params(e->steering_btm_params,&p->val.via.map, 7))
                      {
                          MeshInfo(("dot11vParamBandSteering failed\n"));
                          return -1;
                      }
                  }
                  else if( 0 == match(p, "dot11vParamStickyClientSteering") )
                  {
                      e->sticky_btm_params = malloc( sizeof(sp_btm_params_t));
                      memset(e->sticky_btm_params, 0, sizeof(sp_btm_params_t));
                      if( 0 != process_bs_11kv_params(e->sticky_btm_params,&p->val.via.map, 8))
                      {
                          MeshInfo(("dot11vParamStickyClientSteering failed\n"));
                          return -1;
                      }
                  }
                  else if( 0 == match(p, "gwOnlyOverlay"))
                  {
                      e->for_gw_only = malloc( sizeof(sp_gw_only_t));
                      memset(e->for_gw_only, 0, sizeof(sp_gw_only_t));
                      if( 0 != process_bs_gw_only_params(e->for_gw_only,&p->val.via.map,is_6g))
                      {
                          MeshInfo(("gwOnlyOverlay failed\n"));
                          return -1;
                      }
                  }
                  else
                      MeshInfo("Invalid steering data4\n");

              }
        }
        --objects_left;
        p++;
    }
    return (0 == objects_left) ? 0 : -1;
}

/* See helper.h for details. */
void destroy_bsdoc(void *data)
{
    sp_band_steering_t *mb = (sp_band_steering_t *) data;
    if(NULL != mb)
        free( mb);
}

int process_bsdoc(void *data,int num, ...)
{

//To access the variable arguments use va_list
    va_list valist;
    sp_defaultdoc_t *bs = (sp_defaultdoc_t *)data;
    //sp_band_steering_t *bs = (sp_band_steering_t *) data;
    va_start(valist, num);//start of variable argument loop

    msgpack_object *obj = va_arg(valist, msgpack_object *);//each usage of va_arg fn argument iterates by one time
    msgpack_object_map *mapobj = &obj->via.map;

    va_end(valist);//End of variable argument loop

    if( 0 != process_bsparams(bs,mapobj, false))
    {
        MeshInfo(("process_band steering failed\n"));
        return -1;
    }

    return 0;
}

void destroy_bs_gw_only_doc(void *data)
{
    sp_btm_params_t *gw = (sp_btm_params_t *) data;
    if(NULL != gw)
        free(gw);
}

int process_bs_gw_only_doc(void *data, int num ,...)
{
//To access the variable arguments use va_list
    va_list valist;
    sp_gw_only_t *gw = (sp_gw_only_t *) data;
    va_start(valist, num);//start of variable argument loop

    msgpack_object *obj = va_arg(valist, msgpack_object *);//each usage of va_arg fn argument iterates by one time
    msgpack_object_map *mapobj = &obj->via.map;

    va_end(valist);//End of variable argument loop

    if( 0 != process_bs_gw_only_params(gw,mapobj,true))
    {
        MeshInfo(("process gateway only blob failed\n"));
        return -1;
    }
    return 0;
}

void destroy_bs_sticky_11kvdoc(void *data)
{
    sp_btm_params_t *bs = (sp_btm_params_t *)data;
    if(NULL != bs)
        free(bs);
}

int process_bs_sticky_11kvdoc (void *data, int num ,...)
{
//To access the variable arguments use va_list
    va_list valist;
    sp_btm_params_t *sticky_btm = (sp_btm_params_t *)data;

    va_start(valist, num);//start of variable argument loop
    msgpack_object *obj = va_arg(valist, msgpack_object *);//each usage of va_arg fn argument iterates by one time
    msgpack_object_map *mapobj = &obj->via.map;

    va_end(valist);//End of variable argument loop

    if( 0 != process_bs_11kv_params(sticky_btm,mapobj, 8))
    {
        MeshInfo(("process sticky steering 11kv doc failed\n"));
        return -1;
    }
    return 0;
}
void destroy_bs_11kvdoc(void *data)
{
    sp_btm_params_t *bs = (sp_btm_params_t *) data;
    if(NULL != bs)
        free(bs);
}

int process_bs_11kvdoc (void *data,int num, ...)
{
//To access the variable arguments use va_list
    va_list valist;
    sp_btm_params_t *bs = (sp_btm_params_t *) data;

    va_start(valist, num);//start of variable argument loop
    msgpack_object *obj = va_arg(valist, msgpack_object *);//each usage of va_arg fn argument iterates by one time
    msgpack_object_map *mapobj = &obj->via.map;

    va_end(valist);//End of variable argument loop

    if( 0 != process_bs_11kv_params(bs,mapobj, 7))
    {
        MeshInfo(("process band steering 11kv failed\n"));
        return -1;
    }
    return 0;
}

void destroy_aidoc(void *data)
{
    ai_doc_t *ai = (ai_doc_t *) data;

    if(NULL != ai)
    {
        if(NULL != ai->subdoc_name)
        {
            free(ai->subdoc_name);
            ai->subdoc_name = NULL;
        }
        if(NULL != ai->ai_data)
        {
            free(ai->ai_data);
            ai->ai_data = NULL;
        }
    }
}

void destroy_configsdoc(void *data)
{
    configs_doc_t *configs = (configs_doc_t *) data;
    if(NULL != configs)
    {
        if(NULL != configs->subdoc_name)
        {
            free( configs->subdoc_name);
            configs->subdoc_name = NULL;
        }
        if(NULL != configs->config_data)
        {
            if(configs->config_data->name)
            {
                 free(configs->config_data->name);
                 configs->config_data->name = NULL;
            }
            if (configs->config_data->type  == TYPE_STRING)
            {
                if(configs->config_data->value.string_value)
                {
                    free(configs->config_data->value.string_value);
                    configs->config_data->value.string_value = NULL;
                }
            }
            free(configs->config_data);
            configs->config_data = NULL;
        }
    }
}

void destroy_dpdoc(void *data)
{
    dp_doc_t *dp = (dp_doc_t *) data;
    if(NULL != dp)
    {   
        if(NULL != dp->subdoc_name)
        {   
            free( dp->subdoc_name);
            dp->subdoc_name = NULL;
        }
        if(NULL != dp->clients)
        {   
            free( dp->clients);
            dp->clients = NULL;
        }
        free(dp);
        dp = NULL;
    }
}

void destroy_spsteeringdoc(void *data)
{
    sp_doc_t *mb = (sp_doc_t *)data;

    if(NULL != mb)
    {   
        if(NULL != mb->subdoc_name)
            free( mb->subdoc_name );

        if(NULL != mb->sp_default)
        {   
            if(NULL != mb->sp_default->band_steer)
            {   
                if(mb->sp_default->band_steer->band_steering_6g)
                {   
                    free(mb->sp_default->band_steer->band_steering_6g);
                    mb->sp_default->band_steer->band_steering_6g = NULL;
                }
                if(mb->sp_default->band_steer->steering_btm_params)
                {   
                    free(mb->sp_default->band_steer->steering_btm_params);
                    mb->sp_default->band_steer->steering_btm_params = NULL;
                }
                if(mb->sp_default->band_steer->sticky_btm_params)
                {   
                    free(mb->sp_default->band_steer->sticky_btm_params);
                    mb->sp_default->band_steer->sticky_btm_params = NULL;
                }
                if(mb->sp_default->band_steer->for_gw_only)
                {   
                    if(mb->sp_default->band_steer->for_gw_only->gw_only_6g)
                    {   
                        free(mb->sp_default->band_steer->for_gw_only->gw_only_6g);
                        mb->sp_default->band_steer->for_gw_only->gw_only_6g = NULL;
                    }
                    free(mb->sp_default->band_steer->for_gw_only);
                    mb->sp_default->band_steer->for_gw_only = NULL;
               }
               free( mb->sp_default->band_steer);
               mb->sp_default->band_steer = NULL;
           }

           if(NULL != mb->sp_default->band_steer_6g)
           {   
               if(mb->sp_default->band_steer_6g->band_steering_6g)
               {   
                   free(mb->sp_default->band_steer_6g->band_steering_6g);
                   mb->sp_default->band_steer_6g->band_steering_6g = NULL;
               }
               if(mb->sp_default->band_steer_6g->steering_btm_params)
               {   
                   free(mb->sp_default->band_steer_6g->steering_btm_params);
                   mb->sp_default->band_steer_6g->steering_btm_params = NULL;
               }
               if(mb->sp_default->band_steer_6g->sticky_btm_params)
               {   
                   free(mb->sp_default->band_steer_6g->sticky_btm_params);
                   mb->sp_default->band_steer_6g->sticky_btm_params = NULL;
               }
              if(mb->sp_default->band_steer_6g->for_gw_only)
              {  
                 if(mb->sp_default->band_steer_6g->for_gw_only->gw_only_6g)
                 {   
                     free(mb->sp_default->band_steer_6g->for_gw_only->gw_only_6g);
                     mb->sp_default->band_steer_6g->for_gw_only->gw_only_6g = NULL;
                 }
                 free(mb->sp_default->band_steer_6g->for_gw_only);
                 mb->sp_default->band_steer_6g->for_gw_only = NULL;
             }   
                 free( mb->sp_default->band_steer_6g);
                 mb->sp_default->band_steer_6g = NULL;
        }

        if(NULL != mb->sp_default->client_steering)
        {
            if(mb->sp_default->client_steering)
            {
                free(mb->sp_default->client_steering->kv_params_direct);
                mb->sp_default->client_steering->kv_params_direct = NULL;
                free(mb->sp_default->client_steering);
                mb->sp_default->client_steering = NULL;
            }
        }
        if(NULL != mb->sp_default->dfs)
        {
            free(mb->sp_default->dfs);
            mb->sp_default->dfs = NULL;
        }
        if(NULL != mb->device)
        {
            int i;
            for (i = 0;i < mb->device->count;i++)
            {
                if(mb->device->profiles[i].bandSteering)
                {
                    if(mb->device->profiles[i].bandSteering->gwOnly)
                    {
                        free(mb->device->profiles[i].bandSteering->gwOnly);
                        mb->device->profiles[i].bandSteering->gwOnly = NULL;
                    }
                    free(mb->device->profiles[i].bandSteering);
                    mb->device->profiles[i].bandSteering = NULL;
                }
                if(mb->device->profiles[i].bandSteering6g)
                {
                    if(mb->device->profiles[i].bandSteering6g->gw_only_6g)
                    {
                        free(mb->device->profiles[i].bandSteering6g->gw_only_6g);
                        mb->device->profiles[i].bandSteering6g->gw_only_6g = NULL;
                    }
                    free(mb->device->profiles[i].bandSteering6g);
                    mb->device->profiles[i].bandSteering6g = NULL;
                }
            }
            if(mb->device->profiles)
            {
                free(mb->device->profiles);
                mb->device->profiles = NULL;
            }

            free(mb->device);
            mb->device = NULL;
        }
        free( mb->sp_default);
        mb->sp_default = NULL;
    }
    free(mb);
    mb = NULL;
    }
}

int process_configsdoc( void  *data,int num, ... )
{
    //To access the variable arguments use va_list
    va_list valist;
    int i;

    configs_doc_t *co = (configs_doc_t *)data;

    va_start(valist, num);//start of variable argument loop

    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_array *array = &obj->via.array;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    co->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    co->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);

    co->transaction_id = (uint16_t) obj3->via.u64;
    va_end(valist);//End of variable argument loop

    co->count = array->size;
    co->config_data = malloc( sizeof(configs_t)*co->count);
    memset(co->config_data, 0, (sizeof(configs_t)*co->count));
    MeshInfo("configs_doc count : %d\n",co->count);
    for( i = 0; i < co->count; i++ )
    {
        if( 0 != process_configs(&co->config_data[i], &array->ptr[i].via.map) )
        {
            MeshInfo("process_configsdoc failed\n");
            return -1;
        }
    }
    return 0;
}

int process_aidoc( void  *data,int num, ... )
{
    //To access the variable arguments use va_list
    va_list valist;
    int i;

    ai_doc_t *ai = (ai_doc_t *)data;

    va_start(valist, num);//start of variable argument loop

    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_array *array = &obj->via.array;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    ai->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    ai->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);

    ai->transaction_id = (uint16_t) obj3->via.u64;
    va_end(valist);//End of variable argument loop

    ai->count = array->size;
    ai->ai_data = malloc( sizeof(interference_t)*ai->count);
    memset(ai->ai_data, 0, (sizeof(interference_t)*ai->count));
    MeshInfo("ai_doc count : %d\n",ai->count);
    for( i = 0; i < ai->count; i++ )
    {
        if( 0 != process_ai(&ai->ai_data[i], &array->ptr[i].via.map) )
        {
            MeshInfo("process_ai failed\n");
            return -1;
        }
    }
    return 0;
}

int process_dpdoc( void  *data,int num, ... )
{
    //To access the variable arguments use va_list
    va_list valist;
    int i, left;

    dp_doc_t *dp = (dp_doc_t *)data;

    va_start(valist, num);//start of variable argument loop

    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_array *array = &obj->via.array;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    dp->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    dp->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);

    dp->transaction_id = (uint16_t) obj3->via.u64;
    va_end(valist);//End of variable argument loop

    left = array->size;
    dp->count = array->size;
    dp->clients = malloc( sizeof(clients_t)*left);
    memset(dp->clients, 0, sizeof(clients_t)*left);
    for( i = 0; i < left; i++ )
    {
        if( 0 != process_client_profile(&dp->clients[i], &array->ptr[i].via.map) )
        {   
            MeshInfo("process_client_profile failed\n");
            return -1;
        }
    }
    return 0;
}

int process_spsteeringdoc( void  *data,int num, ... )
{
    //To access the variable arguments use va_list
    va_list valist;
    msgpack_object_kv *p;

    sp_doc_t *sp = (sp_doc_t *)data;

    va_start(valist, num);//start of variable argument loop

    msgpack_object *obj = va_arg(valist, msgpack_object *);
    msgpack_object_map *mapobj = &obj->via.map;

    msgpack_object *obj1 = va_arg(valist, msgpack_object *);
    sp->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

    msgpack_object *obj2 = va_arg(valist, msgpack_object *);
    sp->version = (uint32_t) obj2->via.u64;

    msgpack_object *obj3 = va_arg(valist, msgpack_object *);

    sp->transaction_id = (uint16_t) obj3->via.u64;
    sp->sp_default= malloc( sizeof(sp_defaultdoc_t));
    memset(sp->sp_default, 0, sizeof(sp_defaultdoc_t));
    sp->device = malloc( sizeof(DeviceSpecificProfiles_t));
    memset(sp->device, 0, sizeof(DeviceSpecificProfiles_t));

    va_end(valist);//End of variable argument loop
    p = mapobj->ptr;


    int left = mapobj->size;
    while( (0 < left--) )
    {   
        if( MSGPACK_OBJECT_STR == p->key.type )
        {   
            if( MSGPACK_OBJECT_MAP == p->val.type )
            {
                if( 0 == match(p, "steeringprofiledefaults"))
                {
                    if( 0 != process_bsdefaultprofile(sp->sp_default,&p->val.via.map))
                    {   
                        MeshInfo(("process steeringprofiledefaults failed\n"));
                        return -1;
                    }
                }
            }
            if(MSGPACK_OBJECT_ARRAY == p->val.type)
            {
                if( 0 == match(p, "devicespecificprofiles"))
                {
                    if( 0 != process_device_profile(sp->device,&p->val.via.array))
                    {
                        return -1;
                    }
                }
            }
        }
        p++;   
    }
    return 0;
}

int process_device_profile( DeviceSpecificProfiles_t *device, msgpack_object_array *array )
{
    if( 0 < array->size )
    {
        size_t i;

        MeshInfo("Device profile array size == %d\n",array->size);
        device->count = array->size;
        device->profiles =  malloc(array->size *  sizeof(DeviceSpecificProfile_t));
        for( i = 0; i < array->size; i++ )
        {
            if( MSGPACK_OBJECT_MAP != array->ptr[i].type )
            {
                errno = MB_INVALID_OBJECT;
                return -1;
            }
            memset( (device->profiles + i), 0, sizeof(DeviceSpecificProfile_t));
            if( 0 != process_device_profiles(&device->profiles[i], &array->ptr[i].via.map))
            {
                MeshInfo("process_device_profiles failed\n");
                return -1;
            }
        }
    }
    return 0;
}
