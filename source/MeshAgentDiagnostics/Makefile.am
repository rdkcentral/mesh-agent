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
# if FEATURE_WAN_FAIL_OVER
AM_CFLAGS =
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libXmeshDiags.la
libXmeshDiags_la_SOURCES  = xmesh_diag_apis.c
libXmeshDiags_la_LDFLAGS  = -pthread
libXmeshDiags_la_CPPFLAGS = -I$(top_srcdir)/source/MeshAgentDiagnostics

bin_PROGRAMS = xmesh_diagnostics
xmesh_diagnostics_SOURCES = xmesh_diag_main.c
xmesh_diagnostics_LDADD = libXmeshDiags.la
# endif # FEATURE_WAN_FAIL_OVER
