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

#ifndef _MESHAGENT_H_
#define _MESHAGENT_H_
#include <stdbool.h>
#include "meshsync_msgs.h"

#define MESHAGENT_COMPONENT_NAME		"MeshAgent"

/**
 * @brief Enables or disables debug logs.
 */
#define MESHAGENT_LOG_ERROR                 0
#define MESHAGENT_LOG_INFO                  1
#define MESHAGENT_LOG_WARNING               2
#define MESHAGENT_LOG_DEBUG                 3
#define MeshError(...)                   _MESHAGENT_LOG(MESHAGENT_LOG_ERROR, __VA_ARGS__)
#define MeshInfo(...)                    _MESHAGENT_LOG(MESHAGENT_LOG_INFO, __VA_ARGS__)
#define MeshWarning(...)                 _MESHAGENT_LOG(MESHAGENT_LOG_WARNING, __VA_ARGS__)
#define MeshDebug(...)                   _MESHAGENT_LOG(MESHAGENT_LOG_DEBUG, __VA_ARGS__)

#define PARTNER_REDIRECTORURL_PARAMNAME  "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.MeshRedirectorURL"
#define CHANNEL_KEEPOUT_FILE       "/nvram/mesh/channelPlan/channelKeepOut.json"
#define HD_RECC_FILE              "/nvram/mesh/channelPlan/hd_recommendation.json"

typedef enum {
    POD_XHS_PORT=0,    //Send Event to meshAgent, once Pod is connected on XHS port
    POD_ETH_PORT,      //Send Event to meshAgent, once Pod is connected on non supported port
    POD_PRIV,     //Send Event to meshAgent, once DHCP ACK on 10.0.0.x sent
    POD_CREATE_TUNNEL, //Send Event to meshAgent, once DHCP ACK on 169.254.85.x sent
    POD_BHAUL_CHANGE,  //Send Event to meshAgent, once DHCP ACK on 192.168.245.x sent
    POD_MAC_POLL,      //Send Event to meshAgent, dnsmasq polls for the ethernet mac addr of Pod
    POD_MAX_MSG,
    DHCP_ADD_LEASE = 19,
    REMOVE_LEASE,
    UPDATE_LEASE
} detectionMsg;

/**
 * @brief Initializes the Message Bus and registers component with the stack.
 *
 * @param[in] name Component Name.
 * @return status 0 for success and 1 for failure
 */
int msgBusInit(const char *name);

/**
 * @brief LOGInit Initialize RDK Logger
 */
void LOGInit();

/**
 * @brief _MESHAGENT_LOG MESHAGENT RDK logger API
 */

void _MESHAGENT_LOG(unsigned int level, const char *msg, ...)
    __attribute__((format (printf, 2, 3)));

/**
 * @brief Mesh Agent Get Url
 *
 * This function will set the url and notify the Mesh vendor of the change
 */
int Mesh_GetUrl(char *retBuf, int bufSz);

/**
 * @brief Mesh Agent Set Url
 *
 * This function will set the url and notify the Mesh vendor of the change
 */
bool Mesh_SetUrl(char *url, bool init);

/**
 * @brief Mesh Agent Enable/Disable
 *
 * This function will enable/disable the Mesh service
 */
bool Mesh_SetEnabled(bool enable, bool init, bool commitSyscfg);

/**
 * @brief Mesh Agent Set Mesh State
 *
 * This function will set the state of the Mesh Service.
 * Full, Monitor, etc.
 */
bool Mesh_SetMeshState(eMeshStateType state, bool init, bool commit);

/**
 * @brief Mesh Agent Set Mesh Wifi optimization
 *
 * This function will set the Mesh Wifi Optimization mode.
 * off, monitor, offline.
 */
bool Mesh_SetMeshWifiOptimizationMode(eWifiOptimizationMode uValue, bool init, bool commitSyscfg);


/**
 * @brief Mesh Agent Set Mesh_SetReinitPeriod
 *
 * This function will set the Mesh_SetReinitPeriod.
 * 
 */
bool Mesh_SetReinitPeriod(int puLong,bool init, bool commitSyscfg);

/**
 * @brief Mesh Agent Set Mesh mqtt broker
 *
 * This function will set the Mesh mqtt broker ip and port..
 */
bool Mesh_SetMeshWifiOptimizationMqttBroker(char *broker, bool init, bool commitSyscfg);

/**
 * @brief Mesh Agent Set Ca Cert
 *
 * This function will set Ca Cert Used
 */
bool Mesh_SetMeshCaCert(bool enable, bool init, bool commitSyscfg);

/**
 * @brief Mesh Agent Set Ca Cert
 *
 * This function will send recorder config rbus
 */
bool Mesh_sendRecorderConfig();

/**
 * @brief Mesh Agent enable/disable DscpInheritKernelModule
 *
 * This function will set  dscp_inherit kernel module rfc
 */
bool Mesh_SetMeshDscpInheritKernelModule(bool enable, bool init, bool commitSyscfg);

/**
 * @brief Mesh Agent handle dscp inherit kernel module
 *
 * This function will insert and remove dscp kernel module based
 * on the rfc.
 */
bool Mesh_handleDscpInheritKernelModule(bool enable);

/**
 * @brief Mesh Agent Ge tEnable/Disable
 *
 * This function will enable/disable the Mesh service
 */
bool Mesh_GetEnabled(const char *name);

/**
 * @brief Mesh Agent Update Connected Device
 *
 * This function will update the connected device table and notify
 * Mesh of changes
 */
bool Mesh_UpdateConnectedDevice(char *mac, char *iface, char *host, char *status);
#endif /* _MESHAGENT_H_ */
