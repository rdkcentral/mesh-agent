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

#ifndef __MESH_RBUS_H__
#define __MESH_RBUS_H__
#include <rbus.h>
#include "meshagent.h"

typedef enum {
    MESH_TYPE_BOOL,
    MESH_TYPE_INT,
    MESH_TYPE_STRING
}rbus_type_t;

typedef enum
{
    MWO_TOS_CONFIGURATION = 0,
    MWO_CLIENT_TO_PROFILE_MAP_EVENT,
#if defined(ONEWIFI) || defined(WAN_FAILOVER_SUPPORTED)
    MESH_RBUS_PUBLISH_WAN_LINK,
    MESH_RBUS_PUBLISH_BACKHAUL_IFNAME,
    MESH_RBUS_PUBLISH_ETHBACKHAUL_UPLINK,
#endif
    RECORDER_ENABLE_EVENT,
    CHANNEL_KEEP_OUT_EVENT,
    HD_RECOMMENDATION_EVENT,
    CHANNEL_PLAN_COMMIT,
    MESH_RBUS_PUBLISH_EVENT_TOTAL
} eMeshRbusPublishType;

#define EVENT_MESH_ETHERNETBHAUL_UPLINK  "Device.X_RDK_MeshAgent.EthernetBhaulUplink.Status"
#define EVENT_MESH_WAN_LINK              "Device.X_RDK_MeshAgent.MeshWANLink.Status"
#define EVENT_MESH_WAN_IFNAME            "Device.X_RDK_MeshAgent.MeshWANLink.Interface.Name"
#define EVENT_MESH_BACKHAUL_IFNAME       "Device.X_RDK_MeshAgent.MeshBackHaul.Ifname"
#ifdef WAN_FAILOVER_SUPPORTED
#define NUM_OF_RBUS_PARAMS                10
#else
#define NUM_OF_RBUS_PARAMS                6
#endif
#define EVENT_MWO_TOS_CONFIGURATION      "Device.X_RDK_MeshAgent.MWO.SteeringProfileData"
#define EVENT_MWO_CLIENT_TO_PROFILE_MAP_EVENT "Device.X_RDK_MeshAgent.MWO.ClientProfileData"
#define EVENT_RECORDER_ENABLE            "Device.X_RDK_MeshAgent.Recorder.Enable"
#define EVENT_CHANNEL_KEEPOUT            "Device.X_RDK_MeshAgent.Mesh.ChannelPlan.Data.KeepOut"
#define EVENT_HD_RECOMMENDATION          "Device.X_RDK_MeshAgent.Mesh.ChannelPlan.Data.HDrecc"
#define EVENT_CHANNELPLAN_COMMIT         "Device.X_RDK_MeshAgent.Mesh.ChannelPlan.Commit"
#define MAX_IFNAME_LEN       64
#define  CCSP_COMPONENT_ID                                      "com.cisco.spvtg.ccsp.meshagent"

typedef struct _MeshRbusPublishEvent
{
   eMeshRbusPublishType eType;
   char name[MAX_IFNAME_LEN];
   rbus_type_t rbus_type;
   unsigned int subflag;
}MeshRbusPublishEvent;

rbusError_t publishRBUSEvent(eMeshRbusPublishType ptype , void *val, rbusHandle_t handle);

#endif
