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

#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ethpod_error_det.h"
#include "cosa_mesh_parodus.h"
#include "meshagent.h"

#define POD_TIMEOUT_MS 60000

typedef enum _connstate {
    POD_DISCONNECTED_ST,
    POD_DETECTED_ST,
    POD_VLAN_CONNECTED_ST,
    POD_CONNECTED_ST
} PodConnState;

typedef struct _podstate {
    PodConnState state;
    char mac[MAX_MAC_ADDR_LEN];   //TODO: replace with fixed size string
    uint64_t timeout;
    struct _podstate *next;
} PodState;

//TODO: return some status instead of void
static bool getTime(uint64_t* time);
static void handlePodDC(PodState* pod);
static void handleDhcpAckPriv(PodState* pod);
static void handleDhcpAckVlan(PodState* pod);
static void handleDhcpAckBhaul(PodState* pod);

static PodState* pod_list = NULL;
static PodState* pod_list_tail = NULL;

bool meshAddPod(const char *pod_mac) {

    if(pod_mac == NULL) {
        MeshError("Trying to add a new pod with NULL pod_mac\n");
        return false;
    }

    MeshInfo("Adding new pod_mac: %s\n", pod_mac);
    PodState* new_pod = (PodState*) malloc(sizeof(PodState));
    if(new_pod == NULL) {
        MeshError("Failed to allocate memory for new PodState node\n");
        return false;
    }

    memset(new_pod, 0, sizeof(PodState));
    strncpy(new_pod->mac, pod_mac, sizeof(new_pod->mac));
    new_pod->mac[MAX_MAC_ADDR_LEN-1] = 0;
    new_pod->state = POD_DISCONNECTED_ST;
    new_pod->next = NULL;
    new_pod->timeout = 0;

    if(pod_list == NULL) {
        pod_list = new_pod;
        pod_list_tail = new_pod;
        return true;
    }

    pod_list_tail->next = new_pod;
    pod_list_tail = new_pod;
    return true;
}

bool meshRemovePods() {

    if(pod_list == NULL) {
        return true;
    }

    PodState* temp = pod_list;
    while(pod_list != NULL) {
        temp = pod_list->next;
        free(pod_list);
        pod_list = temp;
    }

    pod_list = NULL;
    pod_list_tail = NULL;
    return true;
}

bool meshHandleEvent(const char * pod_mac, EthPodEvent event) {

    PodState* pod = NULL;
    PodState* temp = NULL;


    for(temp = pod_list; temp != NULL; temp = temp->next) {
        if( strcmp(temp->mac, pod_mac) == 0) {
            pod = temp;
            break;
        }
    }

    if(pod == NULL) {
        MeshError("Pod not found in list, mac: %s\n", pod_mac);
        return false;
    }

    switch(event) {
        case DHCP_ACK_PRIV_EVENT:
            MeshInfo("Event DHCP_ACK_PRIV_EVENT recvd, moving to state POD_DETECTED_ST MAC: %s\n", pod->mac);
            handleDhcpAckPriv(pod);
            break;
        case DHCP_ACK_VLAN_EVENT:
            MeshInfo("Event DHCP_ACK_VLAN_EVENT recvd, moving to state POD_VLAN_CONNECTED_ST MAC: %s \n", pod->mac);
            handleDhcpAckVlan(pod);
            break;
        case DHCP_ACK_BHAUL_EVENT:
            MeshInfo("Event DHCP_ACK_BHAUL_EVENT recvd, moving to state POD_CONNECTED_ST MAC: %s \n", pod->mac);
            handleDhcpAckBhaul(pod);
            break;
        case POD_DC_EVENT:
            handlePodDC(pod);
            break;
        default:
            break;
    }

    return true;
}

void meshHandleTimeout() {
    PodState* pod = NULL;
    uint64_t currTime = 0;

    if(pod_list == NULL) {
        return;
    }

    if(getTime(&currTime) == false) {
        MeshError("Failed to fetch the current time.\n");
        return;
    }

    for(pod = pod_list; pod != NULL; pod = pod->next) {
        if(currTime >= pod->timeout && pod->state != POD_DISCONNECTED_ST && pod->state != POD_CONNECTED_ST) {
            MeshInfo("Pod has timed out! mac: %s\n", pod->mac);
            notifyEvent(ERROR, EB_GENERIC_ISSUE, pod->mac);
            //TODO: Send xFi notification
            pod->state = POD_DISCONNECTED_ST;
            pod->timeout = 0;
        }
    }
}

void handlePodDC(PodState* pod) {
    pod->state = POD_DISCONNECTED_ST;
    pod->timeout = 0;
}

void handleDhcpAckPriv(PodState* pod) {
    uint64_t currTime;
    if(getTime(&currTime) == false) {
        MeshError("Failed to get the current time!\n");
        pod->state = POD_DISCONNECTED_ST;
        pod->timeout = 0;
        return;
    }
    pod->state = POD_DETECTED_ST;
    pod->timeout = currTime + POD_TIMEOUT_MS;
}

void handleDhcpAckVlan(PodState* pod) {
    uint64_t currTime;
    if(getTime(&currTime) == false) {
        MeshError("Failed to get the current time!\n");
        pod->state = POD_DISCONNECTED_ST;
        pod->timeout = 0;
        return;
    }

    pod->state = POD_VLAN_CONNECTED_ST;
    pod->timeout = currTime + POD_TIMEOUT_MS;
}

void handleDhcpAckBhaul(PodState* pod) {
    pod->state = POD_CONNECTED_ST;
    pod->timeout = 0;
}

/** Returns current timestamp in milliseconds **/
bool getTime(uint64_t* time) {
    struct timespec tms = {0};
    if(clock_gettime(CLOCK_REALTIME, &tms)) {
        MeshError("Failed to fetch appropriate time\n");
        return false;
    }

    *time = tms.tv_sec * 1000;
    *time += tms.tv_nsec/1000000;
    return true;
}
