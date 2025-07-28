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

#ifndef ETHPOD_ERROR_DET_H
#define ETHPOD_ERROR_DET_H

#include <stdbool.h>

typedef enum _eth_podevent {
    DHCP_ACK_PRIV_EVENT, //10.0.0.x ACK
    DHCP_ACK_VLAN_EVENT,
    DHCP_ACK_BHAUL_EVENT, //192.168.245.a ACK
    POD_DC_EVENT
} EthPodEvent;

bool meshAddPod(const char * pod_mac);
bool meshRemovePods();
bool meshHandleEvent(const char * pod_mac, EthPodEvent event);
void meshHandleTimeout();

#endif
