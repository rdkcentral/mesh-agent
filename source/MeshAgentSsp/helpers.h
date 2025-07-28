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

#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <msgpack.h>

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

size_t b64_decode( const uint8_t *input,
                      const size_t input_size,
                      uint8_t *output );

/**
 *  This function returns a general reason why the conversion failed.
 *
 *  @param errnum the errno value to inspect
 *
 *  @return the constant string (do not alter or free) describing the error
 */
const char* meshbackhauldoc_strerror( int errnum );
void save_steering_profile_tofile(sp_doc_t *sp);
void save_device_profile_tofile(dp_doc_t *dp);
char *steering_profile_event_data_get();
char *wfm_event_data_get();
char *client_profile_event_data_get();
void save_ai_profile_tofile(ai_doc_t *ai);
void save_channel_keepout_tofile(char * payload);
void save_hdrecc_tofile(char * payload);
void* blob_data_convert( const void *buf, size_t len,eBlobType blob_type );
void meshbackhauldoc_destroy( void  *d );
int process_meshdocparams( meshbackhauldoc_t *e, msgpack_object_map *map );
int process_meshbackhauldoc( void *pm, int num, ...);
void destroy_bs_sticky_11kvdoc(void *bs);
void destroy_bs_11kvdoc(void *bs);
void destroy_bsdoc(void *mb);
void destroy_spsteeringdoc(void *mb);
void destroy_dpdoc (void *db);
void destroy_configsdoc (void *configs);
void destroy_aidoc(void *data);
void destroy_wfmdoc (void *wfm);
void destroy_channelplandoc(void *channel_plan);
void destroy_hdrecc_doc(void *hd_recc);
int process_bs_sticky_11kvdoc (void *sticky_btm, int num ,...);
int process_bs_gw_only_doc(void *gw, int num ,...);
int process_bs_11kvdoc (void *bs,int num, ...);
int process_bsdoc(void *bs,int num, ...);
int process_spsteeringdoc( void *sp_default,int num, ... );
int process_dpdoc( void  *data,int num, ... );
int process_configsdoc( void  *data,int num, ... );
int process_aidoc( void  *data,int num, ... );
int process_wfmdoc( void  *data,int num, ... );
int process_channelplandoc (void  *data,int num, ... );
int process_hdrecc_doc (void  *data,int num, ... );
void destroy_bs_gw_only_doc(void *gw);
#endif
