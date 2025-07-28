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
#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([meshagent], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT
GTEST_ENABLE_FLAG = ""

AC_ARG_ENABLE([gtestapp],
             AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
             [
               case "${enableval}" in
                yes) GTEST_SUPPORT_ENABLED=true
                     GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
                no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
               esac
             ],
             [echo "Gtestapp is disabled"])
AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])

FEATURE_WAN_FAIL_OVER=no
AC_ARG_ENABLE([wanfailover],
        AS_HELP_STRING([--enable-wanfailover],[enable wanfailover]),
        [
          case "${enableval}" in
           yes) FEATURE_WAN_FAIL_OVER=yes ;;
           no) AC_MSG_ERROR([wanfailover is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-wanfailover ]) ;;
           esac
           ],
         [echo "wanfailover is disabled."])

AM_CONDITIONAL([FEATURE_WAN_FAIL_OVER], [test $FEATURE_WAN_FAIL_OVER = yes])

FEATURE_DBUS_SUPPORT=no
AC_ARG_ENABLE([dbus],
        AS_HELP_STRING([--enable-dbus],[enable dbus]),
        [
          case "${enableval}" in
           yes) FEATURE_DBUS_SUPPORT=yes ;;
           no) AC_MSG_ERROR([dbus is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-dbus ]) ;;
           esac
           ],
         [echo "dbus is disabled."])

AM_CONDITIONAL([FEATURE_DBUS_SUPPORT], [test $FEATURE_DBUS_SUPPORT = yes])

FEATURE_ONEWIFI=no
AC_ARG_ENABLE([onewifi],
        AS_HELP_STRING([--enable-onewifi],[enable onewifi]),
        [
          case "${enableval}" in
           yes) FEATURE_ONEWIFI=yes ;;
           no) AC_MSG_ERROR([onewifi is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-onewifi ]) ;;
           esac
           ],
         [echo "onewifi is disabled."])

AM_CONDITIONAL([FEATURE_ONEWIFI], [test $FEATURE_ONEWIFI = yes])

FEATURE_GATEWAY_FAILOVER_SUPPORTED=no
AC_ARG_ENABLE([gatewayfailoversupport],
        AS_HELP_STRING([--enable-gatewayfailoversupport],[enable gatewayfailoversupport]),
        [
          case "${enableval}" in
           yes) FEATURE_GATEWAY_FAILOVER_SUPPORTED=yes ;;
           no) AC_MSG_ERROR([gatewayfailoversupport is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-gatewayfailoversupport ]) ;;
           esac
           ],
         [echo "gatewayfailoversupport is disabled."])

AM_CONDITIONAL([FEATURE_GATEWAY_FAILOVER_SUPPORTED], [test $FEATURE_GATEWAY_FAILOVER_SUPPORTED = yes])

FEATURE_RDKB_EXTENDER_ENABLED=no
AC_ARG_ENABLE([rdkb_extender],
        AS_HELP_STRING([--enable-rdkb_extender],[enable rdkb_extender]),
        [
          case "${enableval}" in
           yes) FEATURE_RDKB_EXTENDER_ENABLED=yes ;;
           no) AC_MSG_ERROR([rdkb_extender is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-rdkb_extender ]) ;;
           esac
           ],
         [echo "rdkb_extender is disabled."])

AM_CONDITIONAL([FEATURE_RDKB_EXTENDER_ENABLED], [test $FEATURE_RDKB_EXTENDER_ENABLED = yes])

FEATURE_RDK_LED_MANAGER_ENABLE=no
AC_ARG_ENABLE([rdk_ledmanager],
        AS_HELP_STRING([--enable-rdk_ledmanager],[enable rdk_ledmanager]),
        [
          case "${enableval}" in
           yes) FEATURE_RDK_LED_MANAGER_ENABLE=yes ;;
           no) AC_MSG_ERROR([rdk_ledmanager is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-rdk_ledmanager ]) ;;
           esac
           ],
         [echo "rdk_ledmanager is disabled."])

AM_CONDITIONAL([FEATURE_RDK_LED_MANAGER_ENABLE], [test $FEATURE_RDK_LED_MANAGER_ENABLE = yes])

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES(
    Makefile
    source/Makefile
    source/MeshAgentSsp/Makefile
    source/MeshAgentCore/Makefile
    source/MeshAgentDiagnostics/Makefile
    source/clientTest/Makefile
)

AC_SUBST(GTEST_ENABLE_FLAG)
AC_OUTPUT

