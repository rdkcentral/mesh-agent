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

#include "cosa_meshagent_dml.h"

#include "ansc_platform.h"
#include "cosa_meshagent_internal.h"
#include "meshagent.h"
#include "ssp_global.h"
#include "syslog.h"
#include "ccsp_trace.h"
#include "safec_lib_common.h"
#include <msgpack.h>
#include "cosa_apis_util.h"
#include <trower-base64/base64.h>
#include "helpers.h"

#define DEBUG_INI_NAME  "/etc/debug.ini"
extern bool isXB3Platform;

extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;

/**
 * @brief LOGInit Initialize RDK Logger
 */
void Mesh_EBCleanup();

void LOGInit()
{
#ifdef FEATURE_SUPPORT_RDKLOG
     rdk_logger_init(DEBUG_INI_NAME);
#endif
}

/**
 * @brief _MESHAGENT_LOG MESHAGENT RDK Logger API
 *
 * @param[in] level LOG Level
 * @param[in] msg Message to be logged 
 */
void _MESHAGENT_LOG(unsigned int level, const char *msg, ...)
{
	va_list arg;
	char *pTempChar = NULL;
	int ret = 0;
	unsigned int rdkLogLevel = LOG_DEBUG;

	switch(level)
	{
		case MESHAGENT_LOG_ERROR:
			rdkLogLevel = RDK_LOG_ERROR;
			break;

		case MESHAGENT_LOG_INFO:
			rdkLogLevel = RDK_LOG_INFO;
			break;

		case MESHAGENT_LOG_WARNING:
			rdkLogLevel = RDK_LOG_WARN;
			break;

        case MESHAGENT_LOG_DEBUG:
            rdkLogLevel = RDK_LOG_DEBUG;
            break;
	}
	
	
	if( rdkLogLevel <= RDK_LOG_INFO )
	{
		pTempChar = (char *)malloc(4096);
		if(pTempChar)
		{
			
			va_start(arg, msg);
			ret = vsnprintf(pTempChar, 4096, msg,arg);
			if(ret < 0)
			{
				perror(pTempChar);
			}
			va_end(arg);
			 
			RDK_LOG(rdkLogLevel, "LOG.RDK.MESH", "%s", pTempChar);
			
			if(pTempChar !=NULL)
			{
				free(pTempChar);
				pTempChar = NULL;
			}
			
		}
	}
	
}


/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_Mesh.

    *  MeshAgent_GetParamBoolValue
    *  MeshAgent_GetParamStringValue
    *  MeshAgent_GetParamUlongValue
    *  MeshAgent_SetParamBoolValue
    *  MeshAgent_SetParamStringValue
    *  GreAcc_GetParamBoolValue
    *  GreAcc_SetParamBoolValue
    *  MWO_GetParamStringValue
    *  MWO_SetParamStringValue
    *  OVS_SetParamBoolValue
    *  MeshAgent_Validate
    *  MeshAgent_Commit
    *  MeshAgent_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MeshAgent_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = g_pMeshAgent->meshEnable;
        return TRUE;
    }

    if (strcmp(ParamName, "Disable") == 0)
    {
        *pBool = g_pMeshAgent->SM_Disable;
        return TRUE;
    }

    if (strcmp(ParamName, "PodEthernetBackhaulEnable") == 0)
    {
        MeshInfo("Pod ethernet bhaul mode get\n");
        *pBool = g_pMeshAgent->PodEthernetBackhaulEnable;
        return TRUE; 
    }

    if (strcmp(ParamName, "XleModeCloudCtrlEnable") == 0)
    {
        MeshInfo("Gateway mode cloud enable flag get\n");
        *pBool = g_pMeshAgent->XleModeCloudCtrlEnable;
        return TRUE;
    }

    if (strcmp(ParamName, "Opensync") == 0)
    {
	MeshInfo("Opensync Enable get\n");
	*pBool = g_pMeshAgent->OpensyncEnable;
	return TRUE;
    }

    if (strcmp(ParamName, "UseComodoCa") == 0)
    {
        MeshInfo("Get the cert used for controller/nlb/mqtt connection\n");
        *pBool = g_pMeshAgent->IsComodoCaCertEnabled;
        return TRUE;
    }

    MeshWarning(("Unsupported parameter '%s'\n"), ParamName);

    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        GreAcc_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC GRE Acceleration;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
GreAcc_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = g_pMeshAgent->GreAccEnable;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        OVS_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC Openvswitch;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
OVS_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = g_pMeshAgent->OvsEnable;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

BOOL
XleAdaptiveFh_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = g_pMeshAgent->XleAdaptiveFh_Enable;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

BOOL
SecureBackhaul_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = g_pMeshAgent->SecureBackhaul_Enable;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n",ParamName);

    return FALSE;
}

BOOL
HDRecommendation_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        *pBool = g_pMeshAgent->HDRecommendation_Enable;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MWO_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.
**********************************************************************/
ULONG
MWO_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if(strcmp(ParamName, "Configs") == 0)
    {
        MeshInfo(("MWO Configs Get Not supported\n"));
        /*CID 379980 The called function is unsafe for security related code */
        strncpy(pValue, "", *pUlSize - 1);
        pValue[*pUlSize - 1] = '\0'; // Ensure null-termination
        return 0;
    }

    if(strcmp(ParamName, "SteeringProfileData") == 0)
    {
        MeshDebug(("SteeringProfileData Get Not supported\n"));
        strncpy(pValue, "", *pUlSize - 1);
        pValue[*pUlSize - 1] = '\0'; // Ensure null-termination
        return 0;
    }

    if(strcmp(ParamName, "ClientProfileData") == 0)
    {
        MeshDebug(("ClientProfileData Get Not supported\n"));
        strncpy(pValue, "", *pUlSize - 1);
        pValue[*pUlSize - 1] = '\0'; // Ensure null-termination
        return 0;
    }

    if(strcmp(ParamName, "StatsConfigData") == 0)
    {
        MeshInfo(("StatsConfigData Get Not supported\n"));
        strncpy(pValue, "", *pUlSize - 1);
        pValue[*pUlSize - 1] = '\0'; // Ensure null-termination
        return 0;
    }

    if(strcmp(ParamName, "AugmentedInterference") == 0)
    {
        MeshInfo("AugmentedInterference Get Not supported\n");
        strncpy(pValue, "", *pUlSize - 1);
        pValue[*pUlSize - 1] = '\0'; // Ensure null-termination
        return 0;
    }

    if(strcmp(ParamName, "WifiMotionSettings") == 0)
    {
        MeshInfo("WifiMotionSettings Get Not supported\n");
        strcpy(pValue, "");
        return 0;
    }
    /*CID 379982  Argument pUlSize to format specifier %ln was expected to have type long * but has type ULONG */
    MeshError("Unsupported Namespace:%s size:%lu\n", ParamName,*pUlSize);

    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshGREBackhaulCache_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC MeshGREBackhaulCache

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshGREBackhaulCache_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if ((ind == 0) && (rc == EOK))
    {
        *pBool = g_pMeshAgent->CacheEnable;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshSecuritySchemaLegacy_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC MeshSecuritySchemaLegacy

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshSecuritySchemaLegacy_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if ((ind == 0) && (rc == EOK))
    {
        *pBool = g_pMeshAgent->SecuritySchemaLegacyEnable;
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshRetryReduction_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC MeshRetryReduction;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshRetryReduction_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("Enable",strlen("Enable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        *pBool = g_pMeshAgent->MeshRetryOptimized;
        return TRUE;
    }
    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshPrioritization_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC MeshPrioritization;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshPrioritization_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    /* check the parameter name and return the corresponding value */

    rc = strcmp_s("Enable",strlen("Enable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("Get dscp flag inherit kernel module is enabled \n");
        *pBool =  g_pMeshAgent->dscpInheritRfcEnable;
        return TRUE;
    }
    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MeshAgent_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
MeshAgent_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "URL") == 0)
    {
        errno_t rc = strcpy_s(pValue, *pUlSize, g_pMeshAgent->meshUrl);
        if (rc != EOK)
        {
    	    ERR_CHK(rc);
    	    return -1;
        }
        return 0;
    }

    if (strcmp(ParamName, "MwoBroker") == 0)
    {
        errno_t rc = strcpy_s(pValue, *pUlSize, g_pMeshAgent->meshWifiOptMqttBroker);
        if (rc != EOK)
        {
            ERR_CHK(rc);
            return -1;
        }
        return 0;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_Connected-Client") == 0)
    {
        /*CID 143931 The called function is unsafe for security related code*/
        strncpy(pValue, "", *pUlSize - 1);
        pValue[*pUlSize - 1] = '\0'; // Ensure null-termination
        return 0;
    }

    if (strcmp(ParamName, "Data") == 0)
    {
        MeshInfo(("Data Get Not supported\n"));
        strncpy(pValue, "", *pUlSize - 1);
        pValue[*pUlSize - 1] = '\0'; // Ensure null-termination
        return 0;
    }

    MeshError("Unsupported Namespace:%s\n", ParamName);

    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Recorder_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for RFC Recorder Enable

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Recorder_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    /* check the parameter name and return the corresponding value */

    rc = strcmp_s("Enable",strlen("Enable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("Recorder state \n");
        *pBool =  g_pMeshAgent->recorderEnable;
        return TRUE;
    }

    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MeshAgent_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Status") == 0)
    {
        *puLong = g_pMeshAgent->meshStatus;
        return TRUE;
    }

    if (strcmp(ParamName, "State") == 0)
    {
        *puLong = g_pMeshAgent->meshState;
        return TRUE;
    }

    if (strcmp(ParamName, "Mode") == 0)
    {
        *puLong = g_pMeshAgent->meshWifiOptimizationMode;
        return TRUE;
    }

    if (strcmp(ParamName, "ReinitPeriod") == 0)
    {
       *puLong = g_pMeshAgent->meshReinitPeriod;
       return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}


extern BOOL is_radio_enabled(char *dcs1, char *dcs2);
extern BOOL is_bridge_mode_enabled();
extern BOOL set_wifi_boolean_enable(char *parameterName, char *parameterValue);
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshAgent_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    char rdk_dcs[2][128];
    char vendor_dcs[2][128];
    int i=0;
    errno_t rc = -1;

    rc = strcpy_s(rdk_dcs[0],sizeof(rdk_dcs[0]),"Device.WiFi.Radio.1.X_RDKCENTRAL-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
    rc = strcpy_s(rdk_dcs[1],sizeof(rdk_dcs[1]),"Device.WiFi.Radio.2.X_RDKCENTRAL-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
    rc = strcpy_s(vendor_dcs[0],sizeof(vendor_dcs[0]),"Device.WiFi.Radio.1.X_COMCAST-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
    rc = strcpy_s(vendor_dcs[1],sizeof(vendor_dcs[1]),"Device.WiFi.Radio.2.X_COMCAST-COM_DCSEnable");
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }

    if (strcmp(ParamName, "Enable") == 0)
    {
         if (bValue == TRUE)
         {
              if(is_bridge_mode_enabled())
              {
                   MeshError(("MESH_ERROR:Fail to enable Mesh when Bridge mode is on\n"));
                   return FALSE;
              }
              if(is_radio_enabled(rdk_dcs[0],rdk_dcs[1])) {
                 for(i=0; i<2; i++) {
                   if(rdk_dcs[i][0]!=0 && set_wifi_boolean_enable(rdk_dcs[i], "false")==FALSE) {
                        MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", rdk_dcs[i]);
                        return FALSE;
                   }
                 }
              }
              if(is_radio_enabled(vendor_dcs[0],vendor_dcs[1])) {
                 for(i=0; i<2; i++) {
                   if(vendor_dcs[i][0]!=0 && set_wifi_boolean_enable(vendor_dcs[i], "false")==FALSE) {
                        MeshError("MESH_ERROR:Fail to enable Mesh because fail to turn off %s\n", vendor_dcs[i]);
                        return FALSE;
                   }
                 }
              }
         }
         else {
              if(is_bridge_mode_enabled() && g_pMeshAgent->meshWifiOptimizationMode != MESH_MODE_DISABLE)
              {
                  MeshInfo("In bridge mode, meshWifiOptimization mode is switched to Disabled\n");
                  Mesh_SetMeshWifiOptimizationMode(MESH_MODE_DISABLE, false, true);
              }

              MeshInfo("Mesh disabled, Disable Ethernet bhaul if enabled\n");
              if( g_pMeshAgent->PodEthernetBackhaulEnable)
              {
                MeshInfo("Send Eth Bhaul disable notification to plume\n");
                Mesh_EBCleanup();
                Mesh_SendEthernetMac("00:00:00:00:00:00");
                //Mesh_SetMeshEthBhaul(false,true); 
              } 
         }

        Mesh_SetEnabled(bValue, false, true);
        return TRUE;
    }

    if (strcmp(ParamName, "Disable") == 0)
    {
       if(Mesh_SetSMAPP(bValue))
       {
          g_pMeshAgent->SM_Disable = bValue;
          return TRUE; 
       }
    }

    if (strcmp(ParamName, "UseComodoCa") == 0)
    {
        MeshInfo("Set the cert used for controller/nlb/mqtt connection\n");
        Mesh_SetMeshCaCert(bValue,false,true);
        return TRUE;
    }

    if (strcmp(ParamName, "PodEthernetBackhaulEnable") == 0)
    {
        MeshInfo("Pod ethernet bhaul mode set\n");
        Mesh_SetMeshEthBhaul(bValue,false,true);
        return TRUE;
    }

    if (strcmp(ParamName, "XleModeCloudCtrlEnable") == 0)
    {
        MeshInfo("Gateway mode cloud enable set\n");
#ifdef ONEWIFI
        Mesh_SetXleModeCloudCtrlEnable(bValue,false,true);
#else
        MeshInfo("XleModeCloudCtrlEnable RFC not supported\n");
#endif
        return TRUE;
    }

    if (strcmp(ParamName, "Opensync") == 0)
    {
        MeshInfo("Opensync set\n");
        Opensync_Set(bValue,false,true);
        return TRUE;
    }

    MeshWarning(("Unsupported parameter '%s'\n"), ParamName);

    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        GreAcc_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for GRE Acceleration;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
GreAcc_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (isXB3Platform) {

        if (strcmp(ParamName, "Enable") == 0)
        {
            MeshInfo("Gre Acc mode set\n");
            return Mesh_SetGreAcc(bValue,false, true);
        }

        MeshWarning("Unsupported parameter '%s'\n", ParamName);

        return FALSE;
    }

    MeshWarning("GRE Acc Unsupported '%s'\n", ParamName);

    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        OVS_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for OpenVSwitch;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
OVS_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        MeshInfo("OVS mode set with commit\n");
        return Mesh_SetOVS(bValue,false,true);
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

BOOL
XleAdaptiveFh_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
       MeshInfo("XleAdaptiveFh_State set with commit\n");
       if(Mesh_SetXleAdaptiveFh(bValue))
       {
          g_pMeshAgent->XleAdaptiveFh_Enable = bValue;
          return TRUE;
       }
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

BOOL
SecureBackhaul_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
       MeshInfo("SecureBackhaul_Enable set with commit\n");
       if(Mesh_SetSecureBackhaul(bValue))
       {
          g_pMeshAgent->SecureBackhaul_Enable = bValue;
          return TRUE;
       }
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

BOOL
HDRecommendation_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
       MeshInfo("HDRecommendation_Enable set with commit\n");
       if(Mesh_SetHDRecommendationEnable(bValue, false, true))
       {
          g_pMeshAgent->HDRecommendation_Enable = bValue;
          return TRUE;
       }
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshGREBackhaulCache_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for RFC MeshGREBackhaulCache

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshGREBackhaulCache_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if ((ind == 0) && (rc == EOK))
    {
        MeshInfo("Cache Status flag set to [%s]\n", bValue ? "true" : "false");
        Mesh_SetCacheStatus(bValue, false, true);
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshSecuritySchemaLegacy_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for RFC SecuritySchemaLegacy

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshSecuritySchemaLegacy_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if ((ind == 0) && (rc == EOK))
    {
        MeshInfo("SecuritySchemaLegacy flag set to [%s]\n", bValue ? "true" : "false");
        Mesh_SetSecuritySchemaLegacy(bValue, false, true);
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshRetryReduction_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for MeshRetryReduction

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshRetryReduction_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    rc = strcmp_s("Enable",strlen("Enable"), ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("MeshRetryOptimized flag set\n");
        Mesh_SetMeshRetryOptimized(bValue,false,true);
        return TRUE;
    }
    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshPrioritization_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for MeshPrioritization

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshPrioritization_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    rc = strcmp_s("Enable",strlen("Enable"), ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("MeshPrioritization flag set\n");
        Mesh_SetMeshDscpInheritKernelModule(bValue,false,true);
        return TRUE;
    }
    else
     MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Recorder_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for Recorder;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Recorder_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);


    if (strcmp(ParamName, "Enable") == 0)
    {
        Recorder_SetEnable(bValue,false, true);
        return TRUE;
    }

    MeshWarning("Recorder Unsupported '%s'\n", ParamName);

    return FALSE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:

        BOOL
        RecorderUpload_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value for Recorder Upload;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.
 ***********************************************************************/
BOOL
RecorderUpload_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("Enable",strlen("Enable"),ParamName,&ind);
    ERR_CHK(rc);
    if( (ind == 0) && (rc == EOK))
    {
        MeshInfo("Recorder Upload state \n");
        *pBool =  g_pMeshAgent->hcm_recording_upload_enable;
        return TRUE;
    }
    else
        MeshWarning("Unsupported parameter '%s'\n", ParamName);
    return FALSE;
}

/***********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RecorderUpload_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value for Recorder Upload;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.
***********************************************************************/
BOOL
RecorderUpload_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "Enable") == 0)
    {
        Recorder_UploadEnable(bValue,false, true);
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshAgent_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       puLong
            );

    description:

        This function is called to set Ulong parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       puLong
                The updated ULong value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
MeshAgent_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

    if (strcmp(ParamName, "State") == 0)
    {
        if ((long)puLong >= MESH_STATE_FULL && puLong < MESH_STATE_TOTAL) {
            Mesh_SetMeshState(puLong, false, true);
            return TRUE;
        }
    }

    if (strcmp(ParamName, "Mode") == 0)
    {
        if ((long)puLong >= MESH_MODE_DISABLE && puLong < MESH_MODE_TOTAL) {
            Mesh_SetMeshWifiOptimizationMode(puLong, false, true);
            return TRUE;
        }
    }

    if (strcmp(ParamName, "ReinitPeriod") == 0)
    {
        Mesh_SetReinitPeriod(puLong, false, true);
        return TRUE;
    }

    MeshWarning("Unsupported parameter '%s'\n", ParamName);

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MeshAgent_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                 int                         pString
            );

    description:

       This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
// Currently, SET is not supported for Name parameter

BOOL
MeshAgent_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    BOOL ret = TRUE;
//    int size = 0;

    if (strcmp(ParamName, "URL") == 0)
    {
        Mesh_SetUrl(pString, false);
        return TRUE;
    }

    if (strcmp(ParamName, "MwoBroker") == 0)
    {
        Mesh_SetMeshWifiOptimizationMqttBroker(pString, false, true);
        return TRUE;
    }

    if (strcmp(ParamName, "X_RDKCENTRAL-COM_Connected-Client") == 0)
    {
#ifdef USE_NOTIFY_COMPONENT
        char pIface[12] = {0}; // can be "Ethernet", "WiFi", "MoCA", "Other"
        char pMac[MAX_MAC_ADDR_LEN] = {0};
        char pStatus[12] = {0}; // can be "Online", "Offline"
        char pHost[256] = {0}; // hostname
        char *param;
        char delim[2] = ",";
        int count = 0;
        char* contextStr = NULL;
        errno_t rc = -1;

        param = strtok_r(pString, delim,&contextStr);

        while (param != NULL)
        {
        	    switch (count)
        	    {
        	    case 0: // Connected-Client tag
        	    	break;
        	    case 1: // Interface
                        rc = strncpy_s(pIface, sizeof(pIface), param, sizeof(pIface)-1);
                        if(rc != EOK)
			{
			   ERR_CHK(rc);
			   return FALSE;
			}
        	    	break;
        	    case 2: // Mac Address
                        rc = strncpy_s(pMac, sizeof(pMac), param, sizeof(pMac)-1);
                        if(rc != EOK)
                        {
                           ERR_CHK(rc);
                           return FALSE;
                        }
        	    	break;
        	    case 3: // Status
                        rc = strncpy_s(pStatus, sizeof(pStatus), param, sizeof(pStatus)-1);
                        if(rc != EOK)
                        {
                           ERR_CHK(rc);
                           return FALSE;
                        }
        	    	break;
        	    case 4: // Hostname
                        rc = strncpy_s(pHost, sizeof(pHost), param, sizeof(pHost)-1);
                        if(rc != EOK)
                        {
                           ERR_CHK(rc);
                           return FALSE;
                        }
        	    	break;
        	    default:
        	    	break;
        	    }
                    count ++;
                    param = strtok_r(NULL, delim,&contextStr);
        }

        MeshInfo("Connected-Client Notification : MAC = %s, Iface = %s, Host = %s, Status = %s \n", pMac, pIface, pHost, pStatus);

        Mesh_UpdateConnectedDevice(pMac, pIface, pHost, pStatus);
#endif
        return TRUE;
    }

    if (strcmp(ParamName, "Data") == 0)
    {
        mesh_msgpack_decode(pString,2500, MESH);
        MeshInfo("Received Mesh Data\n");
        return ret;
    }
    MeshError("Unsupported Namespace:%s\n", ParamName);

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        MWO_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                 int                         pString
            );

    description:

       This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
// Currently, SET is not supported for Name parameter

BOOL
MWO_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    BOOL ret = TRUE;

    if (strcmp(ParamName, "Configs") == 0)
    {
        MeshInfo("Received Configs\n");
        mesh_msgpack_decode(pString,500,CONFIGS);
        return ret;
    }

    if (strcmp(ParamName, "AugmentedInterference") == 0)
    {
        MeshInfo("Received AugmentedInterference Configs\n");
        mesh_msgpack_decode(pString,6000,INTERFERENCE);
        return ret;
    }

    if (strcmp(ParamName, "SteeringProfileData") == 0)
    {
        MeshInfo("Received SteeringProfileData\n");
        mesh_msgpack_decode(pString,3500,STEERING_PROFILE_DEFAULT);
        return ret;
    }

    if(strcmp(ParamName, "ClientProfileData") == 0)
    {
        MeshInfo("Received ClientProfileData\n");
        mesh_msgpack_decode(pString,5000,DEVICE);
        return ret;
    }

    if(strcmp(ParamName, "WifiMotionSettings") == 0)
    {
        MeshInfo("Received WifiMotionSettings\n");
        mesh_msgpack_decode(pString,500,WIFI_MOTION);
        return ret;
    }

    MeshError("Unsupported Namespace:%s\n", ParamName);

    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        MeshAgent_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
MeshAgent_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    if(!strlen(pMyObject->meshUrl))
    {  
    	/* Coverity Issue Fix - CID:125155 : Printf Args */
        MeshInfo("%s: Url String is Empty \n", __FUNCTION__);
        rc = strcpy_s(pReturnParamName, *puLength, "Url is empty");
        if(rc != EOK)
	{
	    ERR_CHK(rc);
	}
        return FALSE;
    }

    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MeshAgent_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
MeshAgent_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        MeshAgent_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
MeshAgent_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    PCOSA_DATAMODEL_MESHAGENT       pMyObject     = (PCOSA_DATAMODEL_MESHAGENT)g_pMeshAgent;

    // reset url
    Mesh_GetUrl((char *)pMyObject->meshUrl, sizeof(pMyObject->meshUrl));
    pMyObject->meshState = Mesh_GetMeshState();
    pMyObject->meshEnable = Mesh_GetEnabled(meshSyncMsgArr[MESH_WIFI_ENABLE].sysStr);

    return 0;
}

BOOL
ChannelPlan_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    BOOL ret = TRUE;

    if (strcmp(ParamName, "Data") == 0) {
        ret = mesh_msgpack_decode(pString,2500,CHANNEL_PLAN_DATA);
    } else { 
        MeshError("Unsupported Namespace:%s\n", ParamName);
        return FALSE;
    }
    return ret;
}

