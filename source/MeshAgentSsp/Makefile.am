##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS =

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libMeshAgentSsp.la

libMeshAgentSsp_la_CPPFLAGS = -I$(top_srcdir)/source/MeshAgentCore -I$(top_srcdir)/source/MeshAgentSsp -I$(top_srcdir)/source/MeshAgentDiagnostics -I$(top_srcdir)/source/include -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ovsagent -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus
libMeshAgentSsp_la_SOURCES = ssp_messagebus_interface.c ssp_main.c ssp_action.c dm_pack_datamodel.c plugin_main.c cosa_meshagent_internal.c cosa_meshagent_dml.c cosa_apis_util.c cosa_mesh_apis.c mesh_client_table.c cosa_webconfig_api.c helpers.c cosa_mesh_parodus.c ethpod_error_det.c keepout_json_helpers.c

if !FEATURE_DBUS_SUPPORT
libMeshAgentSsp_la_SOURCES += mesh_rbus.c
else
libMeshAgentSsp_la_CPPFLAGS += -DDBUS_SUPPORT
endif

libMeshAgentSsp_la_LDFLAGS = -lccsp_common -ldl -rdynamic -lutapi -lutctx -lulog -lwebconfig_framework -llibparodus -lmsgpackc -ltrower-base64 -lprint_uptime -lsecure_wrapper -lz -lpthread -lrt $(SYSTEMD_LDFLAGS) -lrbus
libMeshAgentSsp_la_LIBADD = $(top_builddir)/source/MeshAgentDiagnostics/libXmeshDiags.la

if FEATURE_WAN_FAIL_OVER
libMeshAgentSsp_la_CPPFLAGS += -DWAN_FAILOVER_SUPPORTED
endif
if FEATURE_ONEWIFI
libMeshAgentSsp_la_CPPFLAGS += -DONEWIFI
endif
if FEATURE_GATEWAY_FAILOVER_SUPPORTED
libMeshAgentSsp_la_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus
libMeshAgentSsp_la_LDFLAGS += -lrbus
libMeshAgentSsp_la_CPPFLAGS += -DGATEWAY_FAILOVER_SUPPORTED
endif
if FEATURE_RDKB_EXTENDER_ENABLED
libMeshAgentSsp_la_CPPFLAGS += -DRDKB_EXTENDER_ENABLED
endif
if FEATURE_RDK_LED_MANAGER_ENABLE
libMeshAgentSsp_la_CPPFLAGS += -DRDK_LED_MANAGER_EXIST
endif
