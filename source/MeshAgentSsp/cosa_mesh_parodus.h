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

#ifndef _COSA_MESH_PARODUS_H_
#define _COSA_MESH_PARODUS_H_

typedef enum event_id {
    EB_RFC_DISABLED, //When ethernet bhaul RFC is disabled but still pod is connected over ethernet.
    EB_XHS_PORT,     //When pod is connected to etherent port configured for XHS.
    EB_GENERIC_ISSUE, //To cover issues like wrong switch(not supporting vlan passthrough), link down, power cycle of switch etc..
    EVENT_ID_MAX,
} pod_event_id;

typedef enum event_type {
    ERROR, //When device wants to send error notification
    INFO,  //When device wants to send valid info event notification
    EVENT_TYPE_MAX,
} pod_event_type;

bool notifyEvent(pod_event_type evt_type, pod_event_id evt_id, const char * pod_mac);
bool parodusInit();

#endif
