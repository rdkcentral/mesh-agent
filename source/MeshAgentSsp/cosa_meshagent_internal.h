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

#ifndef  _COSA_MESHAGENT_INTERNAL_H
#define  _COSA_MESHAGENT_INTERNAL_H


#include "ansc_platform.h"
#include "ansc_string_util.h"
#include "meshsync_msgs.h"
#include "cosa_webconfig_api.h"


typedef  struct
_COSA_DATAMODEL_MESHAGENT
{
    BOOL                        meshEnable;
    BOOL                        PodEthernetBackhaulEnable;
    BOOL                        XleModeCloudCtrlEnable;
    BOOL                        OvsEnable;
    BOOL                        GreAccEnable;
    BOOL                        OpensyncEnable;
    BOOL                        SM_Disable;
    BOOL                        XleAdaptiveFh_Enable;
    BOOL                        SecureBackhaul_Enable;
    BOOL                        CacheEnable;
    BOOL                        SecuritySchemaLegacyEnable;
    BOOL                        MeshRetryOptimized;
    UCHAR                       meshUrl[256];
    eMeshWifiStatusType         meshStatus;
    eMeshStateType              meshState;
    eWifiOptimizationMode       meshWifiOptimizationMode;
    UCHAR                       meshWifiOptMqttBroker[128];
    ULONG                       meshReinitPeriod;
    BOOL                        meshSteeringProfileDefault;
    BOOL                        meshClientProfileReceived;
    BOOL                        meshwifiMotionEnable;
    BOOL                        IsComodoCaCertEnabled;
    BOOL                        dscpInheritRfcEnable;
    BOOL                        IsdscpConfigEnabled;
    BOOL                        IsPodConnect;
    BOOL                        HDRecommendation_Enable;
    channel_plan_doc_t          *channel_plan_data;
    BOOL                        recorderEnable;
    BOOL                        hcm_recording_upload_enable;
}
COSA_DATAMODEL_MESHAGENT,  *PCOSA_DATAMODEL_MESHAGENT;

/*
    Standard function declaration
*/
ANSC_HANDLE
CosaMeshAgentCreate
    (
        VOID
    );

ANSC_STATUS
CosaMeshAgentInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaMeshAgentRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaDmlMeshAgentInit
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaDmlMeshAgentDeinit
    (
        ANSC_HANDLE                 hThisObject
    );

#endif
