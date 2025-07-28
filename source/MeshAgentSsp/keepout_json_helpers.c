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

#include <cjson/cJSON.h>
#include <syscfg/syscfg.h>
#include <string.h>
#include <errno.h>
#include "secure_wrapper.h"
#include "cosa_webconfig_api.h"
#include "cosa_meshagent_internal.h"
#include "meshagent.h"
#include "mesh_rbus.h"
#include "safec_lib_common.h"

#define PLANID_MAX_LENGTH 64
#define JSON_OBJECT_DELETE(json_obj) \
        if (json_obj) {\
            cJSON_Delete(json_obj);\
            json_obj = NULL;\
        }
#define CHECK_JSON_OBJECT_CREATED(json_obj) \
        if (json_obj == NULL) {\
            MeshError("%s %d JSON object creation failed.\n",__FUNCTION__,__LINE__);\
            goto exit;\
        }
#define PLAN_ID_LEN_VALIDATOR(plan_id) (strlen(plan_id)>0 && strlen(plan_id)<PLANID_MAX_LENGTH)
#define ADD_BANDWIDTH_AND_CHANNEL_TO_JSON(json_obj, bandwidth, channel) \
        cJSON *array = cJSON_CreateArray(); \
        CHECK_JSON_OBJECT_CREATED(array); \
        cJSON *int_item = cJSON_CreateNumber(channel); \
        cJSON_AddItemToArray(array,int_item);       \
        if (bandwidth == HT_320) { \
            cJSON_AddItemToObject(json_obj,"320",array);\
        } else if (bandwidth == HT_160) {\
            cJSON_AddItemToObject(json_obj,"160",array);\
        } else if (bandwidth == HT_80) {\
            cJSON_AddItemToObject(json_obj,"80",array);\
        } else if (bandwidth == HT_20) {\
            cJSON_AddItemToObject(json_obj,"20",array);\
        }

extern COSA_DATAMODEL_MESHAGENT* g_pMeshAgent;

void channel_keepout_radio_config_init(cJSON * json_radio,radio_keepout_channels *radio) {
    int size;
    int i;

    if (radio == NULL) {
        MeshError("Invalid Data\n");
        return;
    }
    cJSON *channels_160 = cJSON_GetObjectItem(json_radio, "160");
    if (channels_160 != NULL) {
        size = cJSON_GetArraySize(channels_160);
        if (size >0) {
            radio->n_ko_channel_160 = size;
            radio->ko_channel_160 = (int *)calloc(size,sizeof(int));
            if (radio->ko_channel_160) {
                for (i = 0; i < size; i++) {
                    cJSON *channel = cJSON_GetArrayItem(channels_160, i);
                    if (channel != NULL) {
                        radio->ko_channel_160[i] = channel->valueint;
                    }
                }
            }
        }
    }
    cJSON *channels_320 = cJSON_GetObjectItem(json_radio, "320");
    if (channels_320 != NULL ) {
        size = cJSON_GetArraySize(channels_320);
        if (size >0) {
            radio->n_ko_channel_320 = size;
            radio->ko_channel_320 = (int *)calloc(size,sizeof(int));
            if (radio->ko_channel_320) {
                for (i = 0; i < cJSON_GetArraySize(channels_320); i++) {
                    cJSON *channel = cJSON_GetArrayItem(channels_320, i);
                    if (channel != NULL) {
                        radio->ko_channel_320[i] = channel->valueint;
                    }
                }
            }
        }
    }
}

void channel_keepout_doc_init(char *buffer)
{
    errno_t rc = -1;
    channel_keep_out *channel_plan = NULL;
    if (buffer == NULL) {
        MeshError("Received invalid string\n");
        return;
    }
    cJSON *json = cJSON_Parse(buffer);
    if (json == NULL) {
        MeshError("JSON string is NULL\n");
        return;
    }
    g_pMeshAgent->channel_plan_data = (channel_plan_doc_t *)calloc(1,sizeof(channel_plan_doc_t));
    if (!g_pMeshAgent->channel_plan_data) {
        MeshError("%s %d Memory allocation failed\n",__FUNCTION__,__LINE__);
        return ;
    }
    channel_plan = (channel_keep_out *)calloc(1,sizeof(channel_keep_out));
    if (!channel_plan) {
        MeshError("%s %d : Memory allocation failed.\n",__FUNCTION__,__LINE__);
        return;
    }
    cJSON *priority = cJSON_GetObjectItem(json, "priority");
    if (priority && cJSON_IsNumber(priority)) {
        channel_plan->priority = priority->valueint;
    }
    cJSON *plan_id = cJSON_GetObjectItem(json, "planId");
    if (plan_id != NULL && cJSON_IsString(plan_id) && (plan_id->valuestring != NULL)) {
        channel_plan->plan_id = (char *)calloc((strlen(plan_id->valuestring)+1),sizeof(char));	
        if (channel_plan->plan_id) {
            rc = strcpy_s(channel_plan->plan_id,strlen(plan_id->valuestring)+1,plan_id->valuestring);
            if (rc != EOK)
                MeshError("%s Error in copying.\n",__func__);	    
        }
    }
    cJSON *channelExclusion = cJSON_GetObjectItem(json, "ChannelExclusion");
    if (channelExclusion == NULL) {
        free_channel_keepout_global();
        return ;
    } 
    cJSON *object = cJSON_GetArrayItem(channelExclusion, 0);
    if (object != NULL) {
        cJSON *radio6G = cJSON_GetObjectItem(object,"radio6G");
        if (radio6G != NULL) {
            channel_keepout_radio_config_init(radio6G,&(channel_plan->config.radio6G));
        }
        cJSON *radio5G = cJSON_GetObjectItem(object,"radio5G");
        if (radio5G != NULL) {
            channel_keepout_radio_config_init(radio5G,&(channel_plan->config.radio5G));
        }
        cJSON *radio2G = cJSON_GetObjectItem(object,"radio2G");
        if (radio2G != NULL) {
            channel_keepout_radio_config_init(radio2G,&(channel_plan->config.radio2G));
        }
    }
    g_pMeshAgent->channel_plan_data->keepout_channel_list = channel_plan;
    cJSON_Delete(json);
}

void channel_bandwidth_and_num_add(cJSON *json_obj, uint8_t * bandwidth, uint16_t * channel) {
    cJSON *json_channel;
    int size;
    if ((json_channel = cJSON_GetObjectItem(json_obj,"320"))) {
        size = cJSON_GetArraySize(json_channel);
        if (size >0) {
            cJSON * channels_320 = cJSON_GetArrayItem(json_channel, 0);
            *channel = channels_320->valueint;
        }
        *bandwidth = HT_320;
    }
    else if ((json_channel = cJSON_GetObjectItem(json_obj,"160"))) {
        size = cJSON_GetArraySize(json_channel);
        if (size >0) {
            cJSON * channels_160 = cJSON_GetArrayItem(json_channel, 0);
            *channel = channels_160->valueint;
        }
        *bandwidth = HT_160;
    }
    else if ((json_channel = cJSON_GetObjectItem(json_obj,"80"))) {
        size = cJSON_GetArraySize(json_channel);
        if (size >0) {
            cJSON * channels_80 = cJSON_GetArrayItem(json_channel, 0);
            *channel = channels_80->valueint;
        }
        *bandwidth = HT_80;
    }
    else if ((json_channel = cJSON_GetObjectItem(json_obj,"20"))) {
        size = cJSON_GetArraySize(json_channel);
        if (size >0) {
            cJSON * channels_20 = cJSON_GetArrayItem(json_channel, 0);
            *channel = channels_20->valueint;
        }
        *bandwidth = HT_20;
    }
}

void hd_recc_doc_init(char *buffer) {
    errno_t rc = -1;
    HD_recc *hd_recommendation = NULL;
    if (buffer == NULL) {
        MeshError("%s Received invalid string\n",__func__);
        return;
    }
    cJSON *json = cJSON_Parse(buffer);
    if (json == NULL) {
        MeshError("%s JSON string is NULL\n",__func__);
        return;
    }
    if (!g_pMeshAgent->channel_plan_data) {
        g_pMeshAgent->channel_plan_data = (channel_plan_doc_t *)calloc(1,sizeof(channel_plan_doc_t));
        if (!g_pMeshAgent->channel_plan_data) {
            MeshError("%s %d Memory allocation failed\n",__FUNCTION__,__LINE__);
            goto exit;
        }
    }
    hd_recommendation = (HD_recc *)calloc(1,sizeof(HD_recc));
    if (!hd_recommendation) {
        MeshError("%s %d : Memory allocation failed.\n",__FUNCTION__,__LINE__);
        goto exit;
    }
    g_pMeshAgent->channel_plan_data->HD_recc = hd_recommendation;
    cJSON *priority = cJSON_GetObjectItem(json, "priority");
    if (priority && cJSON_IsNumber(priority)) {
        hd_recommendation->priority = priority->valueint;
    }
    cJSON *plan_id = cJSON_GetObjectItem(json, "planId");
    if (plan_id != NULL && cJSON_IsString(plan_id) && (plan_id->valuestring != NULL)) {
        hd_recommendation->plan_id = (char *)calloc((strlen(plan_id->valuestring)+1),sizeof(char));	
        if (hd_recommendation->plan_id) {
            rc = strcpy_s(hd_recommendation->plan_id,strlen(plan_id->valuestring)+1,plan_id->valuestring);
            if (rc != EOK)
                MeshError("%s Error in copying.\n",__func__);	    
        }
    }
    cJSON *expiry = cJSON_GetObjectItem(json, "expiry");
    if (expiry && cJSON_IsNumber(expiry)) {
        hd_recommendation->expiry = (uint64_t)expiry->valuedouble;
    }
    cJSON *radio_config = cJSON_GetObjectItem(json, "config");
    if (!radio_config) {
        MeshError("%s :config is NULL\n",__func__);
        free_hd_recc_global();
        cJSON_Delete(json);
        return;
    }
    hd_recommendation->radio_config = (radio_channel_config *)calloc(1,sizeof(radio_channel_config));
    if (!hd_recommendation->radio_config) {
        MeshError("%s %d : Memory allocation failed.\n",__FUNCTION__,__LINE__);
        goto exit;
    }
    cJSON *radio6G = cJSON_GetObjectItem(radio_config, "radio6G");
    if (radio6G != NULL) {
        channel_bandwidth_and_num_add(radio6G,
            &(hd_recommendation->radio_config->radio6G_bandwidth),
            &(hd_recommendation->radio_config->radio6G_channel));
    }
    cJSON *radio5G = cJSON_GetObjectItem(radio_config, "radio5G");
    if (radio5G != NULL) {
        channel_bandwidth_and_num_add(radio5G,
            &(hd_recommendation->radio_config->radio5G_bandwidth),
            &(hd_recommendation->radio_config->radio5G_channel));
    }
    cJSON *radio2G = cJSON_GetObjectItem(radio_config, "radio2G");
    if (radio2G != NULL) {
        channel_bandwidth_and_num_add(radio2G,
            &(hd_recommendation->radio_config->radio2G_bandwidth),
            &(hd_recommendation->radio_config->radio2G_channel));
    }
    cJSON_Delete(json);
    return;
exit:
    free_channel_plan_global();
    cJSON_Delete(json);
    return; 
}

char *channel_keepout_event_data_get(channel_plan_doc_t *channel_plan_data)
{
    int i;
    char *json_string = NULL;
    cJSON *root = NULL, *array = NULL, *radios = NULL, *radio6G = NULL;
    cJSON *radio_6G_160_array = NULL, *radio_6G_320_array = NULL, *int_item = NULL;

    root = cJSON_CreateObject();
    CHECK_JSON_OBJECT_CREATED(root);
    if (channel_plan_data == NULL || channel_plan_data->keepout_channel_list == NULL) {
        MeshInfo ("Received NULL data.\n");
        json_string = cJSON_PrintUnformatted(root);
        goto exit;
    }

    if (channel_plan_data->keepout_channel_list->priority) {
        cJSON_AddNumberToObject(root,"priority",channel_plan_data->keepout_channel_list->priority);
    }
    if (channel_plan_data->keepout_channel_list->plan_id != NULL && 
        PLAN_ID_LEN_VALIDATOR(channel_plan_data->keepout_channel_list->plan_id)) {
        cJSON_AddStringToObject(root, "planId", channel_plan_data->keepout_channel_list->plan_id);
        cJSON_AddStringToObject(root,"version","1.0");
        MeshInfo("TELEMETRY_CHANNEL_PLAN_ENGINE channelKeepOut\n");
        MeshInfo("TELEMETRY_CHANNEL_PLAN_PLANID %s\n",channel_plan_data->keepout_channel_list->plan_id);
    } else {
        MeshError("%s plan_id is NULL for 6G channel keep out blob\n",__func__);
        goto exit;	
    }

    if ((channel_plan_data->keepout_channel_list->config.radio6G.n_ko_channel_160 > 0) || 
        (channel_plan_data->keepout_channel_list->config.radio6G.n_ko_channel_320 > 0)) {
        array = cJSON_CreateArray();
        CHECK_JSON_OBJECT_CREATED(array);
        cJSON_AddItemToObject(root,"ChannelExclusion",array);
      
        radios =  cJSON_CreateObject();
        CHECK_JSON_OBJECT_CREATED(radios);
        cJSON_AddItemToArray(array,radios);
     
        radio6G = cJSON_CreateObject();
        CHECK_JSON_OBJECT_CREATED(radio6G);
        cJSON_AddItemToObject(radios,"radio6G",radio6G);
    }

    if (channel_plan_data->keepout_channel_list->config.radio6G.n_ko_channel_160 > 0) {
        radio_6G_160_array = cJSON_CreateArray();
        CHECK_JSON_OBJECT_CREATED(radio_6G_160_array);
        cJSON_AddItemToObject(radio6G,"160",radio_6G_160_array);
    }
    if (channel_plan_data->keepout_channel_list->config.radio6G.n_ko_channel_320 > 0) {
        radio_6G_320_array = cJSON_CreateArray();
        CHECK_JSON_OBJECT_CREATED(radio_6G_320_array);
        cJSON_AddItemToObject(radio6G,"320",radio_6G_320_array);
    }
    for (i =0; i<channel_plan_data->keepout_channel_list->config.radio6G.n_ko_channel_160;i++) {
         int_item = cJSON_CreateNumber(channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_160[i]);
         cJSON_AddItemToArray(radio_6G_160_array,int_item);
    }
    for (i =0; i<channel_plan_data->keepout_channel_list->config.radio6G.n_ko_channel_320;i++) {
         int_item = cJSON_CreateNumber(channel_plan_data->keepout_channel_list->config.radio6G.ko_channel_320[i]);
         cJSON_AddItemToArray(radio_6G_320_array,int_item);
    }
    if (array == NULL) {
        MeshError("%s Channel exclusion list is empty.\n",__func__);
	goto exit;
    } else {
        MeshInfo("TELEMETRY_CHANNEL_PLAN_EXCLUSION_LIST %s\n",cJSON_PrintUnformatted(array));
    }
    json_string = cJSON_PrintUnformatted(root);

exit :
    JSON_OBJECT_DELETE(root);
    return json_string;
}

int get_json_object_size(cJSON *json_obj)
{
    int size = 0;
    cJSON *child = NULL;
    cJSON_ArrayForEach(child, json_obj) {
        size++;
    }
    return size;
}

char * hd_recommendation_event_data_get(channel_plan_doc_t *channel_plan)
{
    char *json_string = NULL;
    cJSON *root = NULL, *config = NULL, *radio_6g = NULL, *radio_5g = NULL, *radio_2g = NULL;

    MeshInfo("%s \n",__func__);
    root = cJSON_CreateObject();
    CHECK_JSON_OBJECT_CREATED(root);
    if (channel_plan == NULL || channel_plan->HD_recc == NULL) {
        MeshInfo ("%s Received NULL data.\n", __func__);
        json_string = cJSON_PrintUnformatted(root);
        goto exit;
    }

    if (channel_plan->HD_recc->priority) {
        cJSON_AddNumberToObject(root,"priority",channel_plan->HD_recc->priority);
    }
    if (channel_plan->HD_recc->plan_id != NULL && 
        PLAN_ID_LEN_VALIDATOR(channel_plan->HD_recc->plan_id)) {
        cJSON_AddStringToObject(root, "planId", channel_plan->HD_recc->plan_id);
    } else {
        MeshError("%s plan_id is NULL for HD recommendation blob\n",__func__);
        goto exit;	
    }
    if (channel_plan->HD_recc->expiry < (uint64_t)time(NULL)) {
        MeshError("%s Blob time expired\n",__func__);
        channel_plan->HD_recc->is_blob_expired = true;
        goto exit;
    }
    cJSON_AddNumberToObject(root,"expiry",channel_plan->HD_recc->expiry);
    if (channel_plan->HD_recc->radio_config != NULL) {
        config = cJSON_CreateObject();
        CHECK_JSON_OBJECT_CREATED(config);
        cJSON_AddItemToObject(root,"config",config);
        if (channel_plan->HD_recc->radio_config->radio6G_bandwidth != HT_UNSUPPORTED) {
            radio_6g = cJSON_CreateObject();
            CHECK_JSON_OBJECT_CREATED(radio_6g);
            ADD_BANDWIDTH_AND_CHANNEL_TO_JSON(radio_6g,channel_plan->HD_recc->radio_config->radio6G_bandwidth,channel_plan->HD_recc->radio_config->radio6G_channel);
            cJSON_AddItemToObject(config,"radio6G",radio_6g);
        }
        if (channel_plan->HD_recc->radio_config->radio5G_bandwidth != HT_UNSUPPORTED) {
            radio_5g = cJSON_CreateObject();
            CHECK_JSON_OBJECT_CREATED(radio_5g);
            ADD_BANDWIDTH_AND_CHANNEL_TO_JSON(radio_5g,channel_plan->HD_recc->radio_config->radio5G_bandwidth,channel_plan->HD_recc->radio_config->radio5G_channel);
            cJSON_AddItemToObject(config,"radio5G",radio_5g);
        }
        if (channel_plan->HD_recc->radio_config->radio2G_bandwidth != HT_UNSUPPORTED) {
            radio_2g = cJSON_CreateObject();
            CHECK_JSON_OBJECT_CREATED(radio_2g);
            ADD_BANDWIDTH_AND_CHANNEL_TO_JSON(radio_2g,channel_plan->HD_recc->radio_config->radio2G_bandwidth,channel_plan->HD_recc->radio_config->radio2G_channel);
            cJSON_AddItemToObject(config,"radio2G",radio_2g);
        }
        if (get_json_object_size(config) == 0) {
            MeshError("%s :config is empty\n",__func__);
            goto exit;
        }
    }
    json_string = cJSON_PrintUnformatted(root);
exit:
    JSON_OBJECT_DELETE(root);
    return json_string;
}

bool channel_keepout_init() {
    FILE *file;
    char *buffer = NULL;
    long file_size;
    v_secure_system("mkdir -p /nvram/mesh/channelPlan");

    file = fopen(CHANNEL_KEEPOUT_FILE, "r");
    if (file == NULL) {
        MeshError("Error opening the file channel_keepout.json\n");
        return 0;
    }
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size < 0) {
        MeshError("%s Invalid file size\n",__FUNCTION__);
        fclose(file);
        return 0;
    }

    buffer = (char *)calloc((file_size + 1),sizeof(char));
    if (buffer == NULL) {
        MeshError("%s memory allocation failed\n",__FUNCTION__);
        fclose(file);
        return 0;
    }
    if (fread(buffer, 1, file_size, file) < (unsigned int)file_size) {
        MeshError("%s Error in reading the file content\n",__FUNCTION__);
        free(buffer);
        fclose(file);
        return 0;
    }
    buffer[file_size] = '\0';
    channel_keepout_doc_init(buffer);
    free(buffer);
    fclose(file);
    return 1;
}

bool hd_recommendation_init() {
    FILE *file;
    char *buffer = NULL;
    long file_size;
    v_secure_system("mkdir -p /nvram/mesh/channelPlan");

    file = fopen(HD_RECC_FILE, "r");
    if (file == NULL) {
        MeshError("Error opening the file hd_recommendation.json\n");
        return 0;
    }

    if (!g_pMeshAgent->HDRecommendation_Enable)
    {
        MeshInfo("HD Recommendation is disabled. Clearing the persisted recommendation file %s\n", HD_RECC_FILE);
        fclose(file);
        v_secure_system("rm -f " HD_RECC_FILE);
        return 0;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size < 0) {
        MeshError("%s Invalid file size\n",__FUNCTION__);
        fclose(file);
        return 0;
    }

    buffer = (char *)calloc((file_size + 1),sizeof(char));
    if (buffer == NULL) {
        MeshError("%s memory allocation failed\n",__FUNCTION__);
        fclose(file);
        return 0;
    }
    if (fread(buffer, 1, file_size, file) < (unsigned int)file_size) {
        MeshError("%s Error in reading the file content\n",__FUNCTION__);
        free(buffer);
        fclose(file);
        return 0;
    }
    buffer[file_size] = '\0';
    hd_recc_doc_init(buffer);
    free(buffer);
    fclose(file);
    return 1;
}
