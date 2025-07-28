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
#include "mesh_rbus.h"

rbusHandle_t handle;
MeshRbusPublishEvent  meshRbusPublishEvent[] = {
    {MWO_TOS_CONFIGURATION,                    EVENT_MWO_TOS_CONFIGURATION,            MESH_TYPE_STRING,   0},
    {MWO_CLIENT_TO_PROFILE_MAP_EVENT,          EVENT_MWO_CLIENT_TO_PROFILE_MAP_EVENT,  MESH_TYPE_STRING,   0}
#if defined(ONEWIFI) || defined(WAN_FAILOVER_SUPPORTED)
    ,{MESH_RBUS_PUBLISH_WAN_LINK,               EVENT_MESH_WAN_LINK,                    MESH_TYPE_BOOL,     0},
    {MESH_RBUS_PUBLISH_BACKHAUL_IFNAME,        EVENT_MESH_BACKHAUL_IFNAME,             MESH_TYPE_STRING,   0},
    {MESH_RBUS_PUBLISH_ETHBACKHAUL_UPLINK,     EVENT_MESH_ETHERNETBHAUL_UPLINK,        MESH_TYPE_BOOL,     0}
#endif
    ,{RECORDER_ENABLE_EVENT,                   EVENT_RECORDER_ENABLE,                  MESH_TYPE_BOOL,     0},
    {CHANNEL_KEEP_OUT_EVENT,                  EVENT_CHANNEL_KEEPOUT,                   MESH_TYPE_STRING,   0},
    {HD_RECOMMENDATION_EVENT,                  EVENT_HD_RECOMMENDATION,                MESH_TYPE_STRING,   0},
    {CHANNEL_PLAN_COMMIT,                      EVENT_CHANNELPLAN_COMMIT,               MESH_TYPE_STRING,   0}
};

/**
 * @brief Mesh publishRBUSEvent
 *
 * Publish event after event value gets updated
 */
rbusError_t publishRBUSEvent(eMeshRbusPublishType ptype , void *val, rbusHandle_t handle)
{
    rbusEvent_t event;
    rbusObject_t data;
    rbusValue_t value;
    bool event_val;
    rbusError_t ret = RBUS_ERROR_SUCCESS;

    if(!meshRbusPublishEvent[ptype].subflag)
    {   
        MeshInfo("No subscription for %s\n", meshRbusPublishEvent[ptype].name);
        return RBUS_ERROR_NOSUBSCRIBERS;
    }
    //initialize and set new value for the event
    rbusValue_Init(&value);

    switch(meshRbusPublishEvent[ptype].rbus_type)
    {
    case MESH_TYPE_BOOL:
        event_val = *((bool  *)val) ?  true : false;
        rbusValue_SetBoolean(value, event_val);
    break;
    case MESH_TYPE_STRING:
        rbusValue_SetString(value, (char *)val);
    break;
    default:
        MeshError("publishRBUSEvent default parameter\n");
        break;
    }

    //initialize and set rbusObject with desired values
    rbusObject_Init(&data, NULL);
    rbusObject_SetValue(data, meshRbusPublishEvent[ptype].name, value);

    //set data to be transferred
    event.name = meshRbusPublishEvent[ptype].name;
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;
    //publish the event

    ret = rbusEvent_Publish(handle, &event);
    MeshInfo(
        "rbusEvent_Publish for %s : %s action : %s\n",
        CCSP_COMPONENT_ID, meshRbusPublishEvent[ptype].name,
        ret == RBUS_ERROR_SUCCESS ? "sucess" : "failed" );

    //release all initialized rbusValue objects
    rbusValue_Release(value);
    rbusObject_Release(data);
    return ret;
}
