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

#ifndef _RDKB_MESH_UTILS_C_
#define _RDKB_MESH_UTILS_C_

/*
 * @file cosa_apis_util.c
 * @brief Mesh Agent Utilities
 *
 */
#include <errno.h>
#include <stdio.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <unistd.h>
#include "ccsp_trace.h"
#include "cosa_apis_util.h"
#include "meshagent.h"
#include "ansc_wrapper_base.h"
#include "secure_wrapper.h"

#if defined(WAN_FAILOVER_SUPPORTED) || defined(ONEWIFI) || defined(GATEWAY_FAILOVER_SUPPORTED)
#define MAX_TIME_IN_SEC   60
extern MeshStaStatus_node sta;
#endif

#if defined(ONEWIFI)
extern MeshSync_MsgItem meshSyncMsgArr[];
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
static bool is_connected_via_eth = false;
#endif
#ifndef RDK_LED_MANAGER_EXIST
LedAnimation_Msg  meshLedAnimationArr[] = {
    {SOLID,                            "SOLID"},
    {BLINKING_SLOW,                    "BLINK_SLOW"},
    {BLINKING_FAST,                    "BLINK_FAST"}
};

LedColor_Msg  meshLedColorArr[] = {
    {OFF,                             "OFF"},
    {RED,                             "RED"},
    {WHITE,                           "WHITE"}
};
#endif

#define CONTROLLER_CONNECTED          "2"
#define CONTROLLER_CONNECTING         "3"
#define CONTROLLER_CONNECT_FAILURE    "4"
#define STA_DISCONNECTED              "19"
#define UNIT_ACTIVATED_SYSCFG         "unit_activated"
#endif

#define MIN_BUFF                      128
#define MAX_BUFF                      1024
extern int sysevent_fd_gs;
extern token_t sysevent_token_gs;

int Mesh_SyseventGetStr(const char *name, unsigned char *out_value, int outbufsz)
{
    sysevent_get(sysevent_fd_gs, sysevent_token_gs, name, out_value, outbufsz);
    if(out_value[0] != '\0')
        return 0;
    else
        return -1;
}

int Mesh_SyseventSetStr(const char *name, unsigned char *value, int bufsz, bool toArm)
{
    UNREFERENCED_PARAMETER(toArm);
    int retVal = sysevent_set(sysevent_fd_gs, sysevent_token_gs, name, value, bufsz);

#if defined(_COSA_INTEL_USG_ATOM_)
    if (toArm)
    {
        // Send to ARM
        #define DATA_SIZE 1024
        FILE *fp1;
        char buf[DATA_SIZE] = {0};
        int ret = 0;

        // Grab the ATOM RPC IP address
        fp1 = v_secure_popen("r", "cat /etc/device.properties | grep ARM_ARPING_IP | cut -f 2 -d'='");
        if (fp1 == NULL) {
            MeshDebug("Error opening command pipe! \n");
            return FALSE;
        }

        fgets(buf, DATA_SIZE, fp1);

        buf[strcspn(buf, "\r\n")] = 0; // Strip off any carriage returns

        v_secure_pclose(fp1);

        if (buf[0] != 0 && strlen(buf) > 0) {
            MeshDebug("Reported an ARM IP of %s \n", buf);
            ret = v_secure_system("rpcclient %s sysevent set %s '%s';", buf, name, value);
            if(ret != 0) {
                MeshDebug("Failure in executing command via v_secure_system. ret:[%d] \n", ret);
            } 
        }
    }
#endif

    return retVal;
}


/**************************************************************************/
/*! \fn static STATUS G_SysCfgGetInt
 **************************************************************************
 *  \brief Get Syscfg Integer Value
 *  \return int/-1
 **************************************************************************/
int Mesh_SysCfgGetInt(const char *name)
{
   unsigned char out_value[20] = {0};
   
   if (!syscfg_get(NULL, name, out_value, sizeof(out_value)))
   {
      return atoi(out_value);
   }
   else
   {
      MeshInfo(("syscfg_get failed\n"));
      return 0;
   }
}

/**************************************************************************/
/*! \fn static STATUS GWP_SysCfgSetInt
 **************************************************************************
 *  \brief Set Syscfg Integer Value
 *  \return 0:success, <0: failure
 **************************************************************************/
int Mesh_SysCfgSetInt(const char *name, int int_value)
{
   int retval=0;

   retval = syscfg_set_u_commit(NULL, name, int_value);

   return retval;
}

int Mesh_SysCfgGetStr(const char *name, unsigned char *out_value, int outbufsz)
{
   return syscfg_get(NULL, name, out_value, outbufsz);
}

int Mesh_SysCfgSetStr(const char *name, unsigned char *str_value, bool toArm)
{
    UNREFERENCED_PARAMETER(toArm);
   int retval = 0;

   retval = syscfg_set_commit(NULL, name, str_value);


#if defined(_COSA_INTEL_USG_ATOM_)
    if (toArm)
    {
        // Send event to ARM
        #define DATA_SIZE 1024
        FILE *fp1 = NULL;
        char buf[DATA_SIZE] = {0};
        int ret = 0;

        // Grab the ATOM RPC IP address

        fp1 = v_secure_popen("r", "cat /etc/device.properties | grep ARM_ARPING_IP | cut -f 2 -d'='");
        if (fp1 == NULL) {
            MeshDebug("Error opening command pipe! \n");
            return FALSE;
        }

        fgets(buf, DATA_SIZE, fp1);

        buf[strcspn(buf, "\r\n")] = 0; // Strip off any carriage returns

        v_secure_pclose(fp1);

        if (buf[0] != 0 && strlen(buf) > 0) {
            MeshDebug("Reported an ARM IP of %s \n", buf);
            ret = v_secure_system("rpcclient %s \"syscfg set %s %s; syscfg commit\" &", buf, name,str_value);
            if(ret != 0) {
                MeshDebug("Failure in executing command via v_secure_system. ret:[%d] \n", ret);
            }
        }
    }
#endif
   return retval;
}

// Invoke systemctl to get the running/stopped state of a service
int svcagt_get_service_state (const char *svc_name)
{
	int exit_code;
	bool running;

	MeshInfo("In svcagt_get_service_state\n");
        exit_code =v_secure_system ("systemctl is-active %s.service", svc_name);
	if (exit_code == -1) {
		CcspTraceError(("Error invoking systemctl command, errno: %s\n", strerror(errno)));
		return -1;
	}
	running = (exit_code == 0);
	MeshInfo("In svcagt_get_service_state before return\n");
	return running;
}

// Invoke systemctl to start or stop a service
int svcagt_set_service_state (const char *svc_name, bool state)
{
	int exit_code = 0;
	const char *start_stop_msg = NULL;
	const char *cmd_option = NULL;

	if (state) {
		start_stop_msg = "Starting";
		cmd_option = "start";
	} else {
		start_stop_msg = "Stopping";
		cmd_option = "stop";
	}

	MeshInfo("%s %s\n", start_stop_msg, svc_name);

	exit_code = v_secure_system ("systemctl %s %s.service", cmd_option, svc_name);
	if (exit_code != 0)
		CcspTraceError(("Command systemctl %s %s.service failed with exit %d, errno %s\n", cmd_option, svc_name, exit_code, strerror(errno)));
	return exit_code;
}

int svcagt_set_service_restart (const char *svc_name)
{
        int exit_code = 0;

        exit_code = v_secure_system ("systemctl restart %s.service", svc_name);
        if (exit_code != 0)
                CcspTraceError(("Command systemctl restart %s.service failed with exit %d, errno %s\n", svc_name, exit_code, strerror(errno)));
        return exit_code;
}

bool ping_ip (char *ip)
{
    char    cmd[MIN_BUFF],buf[MIN_BUFF],out[MAX_BUFF];
    FILE    *fp;
    size_t  total_read = 0;

    snprintf(cmd, sizeof(cmd), "ping -c 1 %s",ip);
    fp = popen(cmd, "r");
    if (!fp) {
        MeshError("%s - popen failed, errno = %d\n", cmd, errno);
        return errno;
    }
    memset(out, 0, MAX_BUFF);
    while (fgets(buf, MIN_BUFF, fp) != NULL) {
        size_t len = strlen(buf);
        if (total_read + len >= MAX_BUFF) {
            MeshError("Exceeded buffer size, clipping output\n");
            break;
        }
        /*CID 346812 The destination of a strcpy call must have enough space to accept the source.*/
      
        strncpy(out + total_read, buf,MAX_BUFF - total_read - 1);
        total_read += len;
    }

    while(out[strlen(out)-1] == '\r' || out[strlen(out)-1] == '\n') {
        out[strlen(out)-1] = '\0';
    }
    if(pclose(fp)) {
        return false;
    } else {
        return true;
    }
}
#if defined(WAN_FAILOVER_SUPPORTED) || defined(ONEWIFI) || defined(GATEWAY_FAILOVER_SUPPORTED)
int nif_ioctl(int cmd, void *buf)
{
    int fd = -1;
    int rc;
    int retval = 0;
    if (fd < 0)
    {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            MeshInfo("nif_ioctl: socket() failed.\n");
            retval = errno;
            return retval;
        }
    }
    rc = ioctl(fd, cmd, buf);
    if (rc != 0)
    {
        retval = errno;
    }
    close(fd);

    return retval;
}

int nif_ifreq(int cmd, char *ifname, struct ifreq *req)
{
    errno_t rc = -1;
    int tries = 0;

    rc = strcpy_s(req->ifr_name,sizeof(req->ifr_name),ifname);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        MeshError("Error in copying ifname\n");
    }
    while (tries++ < MAX_TIME_IN_SEC)
    {
        rc = nif_ioctl(cmd, req);
       if(rc == 0)
       {
           break;
       }
       MeshError("ioctl: ifname: %s,cmd: %d, %s\n",req->ifr_name,cmd,strerror(errno));
       sleep(1);
    }
    return rc;
}

bool nif_exists(char *ifname, bool *exists)
{
    struct ifreq    req;
    int             rc;

    /*
     * Check if the device exists by retrieving the device index.
     * If this fails the device definitely does not exist.
     * */
    rc = nif_ifreq(SIOCGIFINDEX, ifname, &req);
    if (rc != 0)
    {
        *exists = false;
    }
    else
    {
        *exists = true;
    }

    return true;
}

/*
 * Retrieve the ip address of the interface @p ifname
 */
bool nif_ipaddr_get(char* ifname, os_ipaddr_t* addr)
{
    int             rc;
    struct ifreq    req;

    /* Requesting an internet address */
    req.ifr_addr.sa_family = AF_INET;

    rc = nif_ifreq(SIOCGIFADDR, ifname, &req);
    if (rc != 0)
    {
        MeshInfo("nif_ipaddr: SIOCGIFADDR failed.::ifname=%s\n", ifname);
        return false;
    }

    memcpy(addr, &(((struct sockaddr_in *)&req.ifr_addr)->sin_addr.s_addr),4);

    return true;
}

/*
 * Retrieve the netmask of the interface @p ifname
 */
bool nif_netmask_get(char* ifname, os_ipaddr_t* addr)
{
    int             rc;
    struct ifreq    req;

    /* Requesting an internet address */
    req.ifr_netmask.sa_family = AF_INET;

    rc = nif_ifreq(SIOCGIFNETMASK, ifname, &req);
    if (rc != 0)
    {
        MeshInfo("nif_ipaddr:SIOCGIFNETMASK failed::ifname=%s\n", ifname);
        return false;
    }

    memcpy(addr,
            &((struct sockaddr_in *)&req.ifr_netmask)->sin_addr.s_addr,4);

    return true;
}

bool get_ipaddr_subnet(char * ifname, char *local_ip, char * remote_ip)
{
    int i;
    os_ipaddr_t ipaddr,subnet;
    bool ret = true;

    memset(&ipaddr, 0, sizeof(os_ipaddr_t));
    memset(&subnet, 0, sizeof(os_ipaddr_t));

    MeshInfo("get_ipaddr_subnet: start\n");
    if (nif_ipaddr_get(ifname, &ipaddr))
    {
        if (nif_netmask_get(ifname, &subnet))
        {
            for (i =0; i<MAX_IPV4_BYTES; i++)
            {
                if(subnet.addr[i]!=0)
                    subnet.addr[i] = ipaddr.addr[i];
                else
                    subnet.addr[i] = 1;
            }
            if(snprintf(local_ip,MAX_IP_LEN , PRI(os_ipaddr_t), FMT(os_ipaddr_t, ipaddr)))
                MeshInfo("%s: if_name[%s] local ip addr[%s]\n", __func__, ifname,local_ip);
            if(snprintf(remote_ip,MAX_IP_LEN , PRI(os_ipaddr_t), FMT(os_ipaddr_t, subnet)))
                MeshInfo("%s: if_name[%s] remote ip addr[%s]\n", __func__, ifname,remote_ip);
        }
    }
    else
    {
        MeshInfo("udhcpc: %s interface didnt get ip\n",ifname);
        ret = false;
    }
    return ret;
}

int udhcpc_pid(char *ifname)
{
    char pid_file[256];
    FILE *f;
    int pid;
    int rc;

    snprintf(pid_file, sizeof(pid_file), "/var/run/udhcpc-%s.pid", ifname);
    f = fopen(pid_file, "r");
    if (f == NULL) return 0;
    rc = fscanf(f, "%d", &pid);
    fclose(f);

    /* We should read exactly 1 element */
    if (rc != 1)
    {
        return 0;
    }

    if (kill(pid, 0) != 0)
    {
        return 0;
    }

    return pid;
}

bool udhcpc_start(char* ifname)
{
    char pidfile[256];
    pid_t pid;
    char  udhcpc_s_option[256];
    int status;

    MeshInfo("Mesh udhcpc_start ifname=%s\n",ifname);
    pid = udhcpc_pid(ifname);
    if (pid > 0)
    {
        MeshError("DHCP client already running::ifname=%s\n", ifname);
        return true;
    }

    snprintf(pidfile, sizeof(pidfile), "/var/run/udhcpc-%s.pid", ifname);
    snprintf(udhcpc_s_option, sizeof(udhcpc_s_option), "/usr/opensync/scripts/udhcpc.sh");

    char *argv_apply[] = {
       "/sbin/udhcpc",
       "-p", pidfile,
       "-s", udhcpc_s_option,
       "-i", ifname,
       NULL
    };

    pid = fork();
    if (pid == 0)
    {
        if (fork() == 0)
        {
            MeshInfo("%s: option \n", __func__);
            execv("/sbin/udhcpc", argv_apply);
        }
        exit(0);
    }

    /* Wait for the first child -- it should exit immediately */
    waitpid(pid, &status, 0);

    return true;
}

bool udhcpc_stop(char* ifname)
{
    int pid = udhcpc_pid(ifname);
    MeshInfo("udhcpc_stop is called %s\n", ifname);
    if (pid <= 0)
    {
        MeshInfo("DHCP client not running::ifname=%s\n", ifname);
        return true;
    }

    int signum = SIGTERM;
    int tries = 0;

    while (kill(pid, signum) == 0)
    {
        if (tries++ > 20)
        {
            signum = SIGKILL;
        }

        usleep(100*1000);
    }

    return true;
}

int handle_uplink_bridge(char *ifname, char * bridge_ip, char *pod_addr, bool create)
{
    int rc = -1;

    if(create)
    {
        MeshInfo("Entering %s with ifname = %s, bridge_ip = %s, pod_addr = %s,\n", __FUNCTION__, ifname, bridge_ip, pod_addr);

        rc = v_secure_system("/usr/bin/ovs-vsctl del-br %s", MESH_BHAUL_BRIDGE);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshWarning("Failed to remove bridge %s\n",MESH_BHAUL_BRIDGE);
        }

        MeshInfo("ip link add g-%s type gretap local %s remote %s dev %s tos 1\n", ifname, bridge_ip, pod_addr, ifname);
	rc = v_secure_system("ip link add g-%s type gretap local %s remote %s dev %s tos 1", ifname, bridge_ip, pod_addr, ifname);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("Failed to create g-%s GRE tap with local IP: %s and remote IP %s\n", ifname, bridge_ip, pod_addr);
            return -1;
        }

        MeshInfo("/sbin/ifconfig g-%s up\n", ifname);
        rc = v_secure_system("/sbin/ifconfig g-%s up", ifname);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("Failed to bring g-%s up\n", ifname);
            return -1;
        }

        MeshInfo("/usr/bin/ovs-vsctl add-br %s\n",GATEWAY_FAILOVER_BRIDGE);
        rc = v_secure_system("/usr/bin/ovs-vsctl add-br %s",GATEWAY_FAILOVER_BRIDGE);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("Failed to add bridge %s\n", GATEWAY_FAILOVER_BRIDGE);
            return -1;
        }

        MeshInfo("/usr/bin/ovs-vsctl add-port %s g-%s\n",GATEWAY_FAILOVER_BRIDGE,ifname);
        rc = v_secure_system("/usr/bin/ovs-vsctl add-port %s g-%s",GATEWAY_FAILOVER_BRIDGE,ifname);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("Failed to add g-%s to bridge %s\n", ifname, GATEWAY_FAILOVER_BRIDGE);
            return -1;
        }

        MeshInfo("/sbin/ifconfig %s  up\n", GATEWAY_FAILOVER_BRIDGE);
        rc = v_secure_system("/sbin/ifconfig %s  up", GATEWAY_FAILOVER_BRIDGE);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshError("Failed to bring %s up\n", GATEWAY_FAILOVER_BRIDGE);
            return -1;
        }
    }
    else
    {
        rc = v_secure_system("/usr/bin/ovs-vsctl del-port %s g-%s", GATEWAY_FAILOVER_BRIDGE,sta.sta_ifname);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshWarning("Failed to remove bridge %s from g-%s\n",GATEWAY_FAILOVER_BRIDGE,sta.sta_ifname);
        }
        rc = v_secure_system("ip link del g-%s", sta.sta_ifname);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshWarning("Failed to delete g-%s, maybe it doesn't exist?\n", sta.sta_ifname);
        }
        rc = v_secure_system("/usr/bin/ovs-vsctl del-br %s", GATEWAY_FAILOVER_BRIDGE);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            MeshWarning("Failed to remove bridge %s \n",GATEWAY_FAILOVER_BRIDGE);
        }
    }
    return 0;
}
#if defined(ONEWIFI)
#ifndef RDK_LED_MANAGER_EXIST
/**
 * @brief Led animation
 *
 * This function will control the led animation
 */
void  led_state(eLedColor color,eLedAnimation animation)
{
    int rc = -1;

    MeshInfo("Led Set led_control_script.sh  %s %s\n",  meshLedAnimationArr[animation].animation_str,meshLedColorArr[color].color_str);
    rc = v_secure_system("led_control_script.sh %s %s",meshLedAnimationArr[animation].animation_str,meshLedColorArr[color].color_str);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        MeshError("Led Status for /usr/sbin/led_control_script.sh  %s %s is failed,  return = %d\n",  meshLedAnimationArr[animation].animation_str,meshLedColorArr[color].color_str, WEXITSTATUS(rc));
    }
}
#endif
#if defined(WAN_FAILOVER_SUPPORTED) && defined(RDKB_EXTENDER_ENABLED)
bool is_eth_connected()
{
    return is_connected_via_eth;
}

/**
 * @brief Mesh Agent control led
 *
 * This function will control the led based on connection status
 */
void  handle_led_status(eMeshSyncStatus status, int devicemode)
{
    static bool ctr_status = false;
    static eMeshSyncStatus current_status;

    if (current_status == status)
    {
        MeshInfo("There is not change, state:%d\n", status);
        return;
    }

    switch (status)
    {
        case MESH_CONTROLLER_CONNECTED_VIA_EBH:
        case MESH_CONTROLLER_CONNECTED_VIA_WBH: 
            if (status == MESH_CONTROLLER_CONNECTED_VIA_EBH)
               is_connected_via_eth = true;
            else
               is_connected_via_eth = false;

            ctr_status = true;
            MeshInfo("Led Off, Controller connected\n");
#ifndef RDK_LED_MANAGER_EXIST
            led_state(OFF,SOLID);
#endif
            if(devicemode == EXTENDER_MODE)
                Mesh_SyseventSetStr(meshSyncMsgArr[MESH_SYNC_STATUS].sysStr,CONTROLLER_CONNECTED, 0, false);

            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_CONTROLLER_STATUS].sysStr,CONTROLLER_CONNECTED, 0, false);
        break;
        case MESH_CONTROLLER_CONNECTING:
	    ctr_status = false;
            MeshInfo("Led Blink White, Controller Connecting\n");
#ifndef RDK_LED_MANAGER_EXIST
            led_state(WHITE,BLINKING_SLOW);
#endif
            if(devicemode == EXTENDER_MODE)
                Mesh_SyseventSetStr(meshSyncMsgArr[MESH_SYNC_STATUS].sysStr,CONTROLLER_CONNECTING, 0, false);

            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_CONTROLLER_STATUS].sysStr,CONTROLLER_CONNECTING, 0, false);
            break;
        case MESH_CONTROLLER_FAILURE:
	    ctr_status = false;
            MeshInfo("Led Off, Connection Failure\n");
#ifndef RDK_LED_MANAGER_EXIST
            led_state(OFF,SOLID);
#endif
            if(devicemode == EXTENDER_MODE)
                Mesh_SyseventSetStr(meshSyncMsgArr[MESH_SYNC_STATUS].sysStr,CONTROLLER_CONNECT_FAILURE, 0, false);

            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_CONTROLLER_STATUS].sysStr,CONTROLLER_CONNECT_FAILURE, 0, false);
            break;
        case MESH_STA_DISCONNECTED:
            MeshInfo("Led Blink white, Sta Disconnect\n");
#ifndef RDK_LED_MANAGER_EXIST
            led_state(WHITE,BLINKING_SLOW);
#endif
            if(devicemode == EXTENDER_MODE)
                Mesh_SyseventSetStr(meshSyncMsgArr[MESH_SYNC_STATUS].sysStr,STA_DISCONNECTED, 0, false);

            Mesh_SyseventSetStr(meshSyncMsgArr[MESH_CONTROLLER_STATUS].sysStr,STA_DISCONNECTED, 0, false);
            break;
        case MESH_STA_CONNECTED:
            if(ctr_status == true)
            {
#ifndef RDK_LED_MANAGER_EXIST
                led_state(OFF,SOLID);
#endif
                if(devicemode == EXTENDER_MODE)
                     Mesh_SyseventSetStr(meshSyncMsgArr[MESH_SYNC_STATUS].sysStr,CONTROLLER_CONNECTED, 0, false);

                Mesh_SyseventSetStr(meshSyncMsgArr[MESH_CONTROLLER_STATUS].sysStr,CONTROLLER_CONNECTED, 0, false);
            }
            break;
        case MESH_MQTT_RECVD:
            MeshInfo("MQTT is recvd, turn of BLE\n");
            if(Mesh_SysCfgSetStr(UNIT_ACTIVATED_SYSCFG, "1", true) != 0) {
                MeshInfo("Failed to set the unit_activated in syscfg\n");
            } else {
                MeshInfo("Set the unit_activated in syscfg success\n");
            }
            break;
        default:
            break;
    }
    current_status = status;
}
#endif //WAN_FAILOVER_SUPPORTED && RDKB_EXTENDER_ENABLED
#endif // ONEWIFI
#endif // WAN_FAILOVER_SUPPORTED || ONEWIFI || GATEWAY_FAILOVER_SUPPORTED
#endif // _RDKB_MESH_UTILS_C_
