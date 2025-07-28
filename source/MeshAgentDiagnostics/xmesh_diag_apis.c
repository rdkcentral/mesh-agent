#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include "xmesh_diag.h"
#include  "safec_lib_common.h"

char* getFormattedTime(void) {

    time_t rawtime;
    struct tm* timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    // Must be static, otherwise won't work
    static char _retval[20];
    strftime(_retval, sizeof(_retval), "%Y-%m-%d %H:%M:%S", timeinfo);

    return _retval;
}

int generate_random() {
   int rand_num = 0;
   FILE *fp = fopen("/dev/urandom", "rb");
   size_t result;

   if (fp == NULL) {
       LOGERROR("Error opening /dev/urandom");
       return 0;
   }

   result = fread(&rand_num, sizeof(rand_num), 1, fp);
   fclose(fp);

   if (result !=1) {
       LOGERROR("Error reading /dev/urandom");
       return 0;
   }

   return abs(rand_num);
}

#define MAX_BUFFER_SIZE 32768 // 32kB max buffer required to accommodate some large outputs like OVSDB tables
#define BUF_SIZE 128
#define BUF_IF_NAME 16
#define BUF_IPV4 16 // xxx.xxx.xxx.xxx
#define BUF_MAC  18 // xx:xx:xx:xx:xx:xx

typedef enum {
    MODEL_UNKNOWN = -1,
    MODEL_CGM4331COM,
    MODEL_TG4482PC2,
    MODEL_SIMULATED,
    MODEL_WNXL11BWL
} device_model_t;

typedef struct _commands_t {
    char desc[128];
    char cmd[256];
} commands_t;

typedef struct _diag_args_t {
    int  interval;
    bool dumps_enabled;
    bool wfo;
    int  delay;
    device_model_t model;
} diag_args_t;

typedef struct _count_t {
    int total_iter;
    int count_all_good;
    int not_wfo;
    int xb_no_actv_iface;
    int xb_meshwanlink_bad;
    int xb_no_pods_connected;
    int xb_xle_no_ip;
    int xb_no_pgd;
    int xb_no_dev_detected;
    int xb_pgd_not_in_br403;
    int xb_brrwan_no_ip;
    int xb_brwan_unreach;
    int xb_brrwan_not_default;
    int xb_no_internet_brrwan;
    int xle_bhaul_no_conn;
    int xle_bhaul_no_ip;
    int xle_gre_remote_unreach;
    int xle_brhome_error;
    int xle_brwan_no_ip;
    int xle_brwan_no_gre;
    int xle_mgw_unreachable;
    int xle_brrwan_conn_fail;
    int xle_wwan0_offline;
    int no_internet;
} count_t;

count_t g_count;
static pthread_t xmesh_tid;
static pthread_mutex_t xmesh_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool   g_xmesh_active = false;
static struct timespec g_start_time;

/**
 * Root Servers based on https://www.iana.org/domains/root/servers
 */
static char *g_root_servers[] = {
    "a.root-servers.net",
    "b.root-servers.net",
    "c.root-servers.net",
    "d.root-servers.net",
    "e.root-servers.net",
    "f.root-servers.net",
    /* "g.root-servers.net", */
    "h.root-servers.net",
    "i.root-servers.net",
    "j.root-servers.net",
    "k.root-servers.net",
    "l.root-servers.net",
    "m.root-servers.net"
};
static char *g_root_servers_ipv4[] = {
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    /* "192.112.36.4", */
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33"
};

static int GetFirmwareName (char *pValue, unsigned long maxSize)
{
    static char name[64];

    if (name[0] == 0)
    {
        FILE *fp;
        char buf[128];  /* big enough to avoid reading incomplete lines */
        char *s = NULL;
        size_t len = 0;

        if ((fp = fopen ("/version.txt", "r")) != NULL)
        {
            while (fgets (buf, sizeof(buf), fp) != NULL)
            {
                /*
                   The imagename field may use either a ':' or '=' separator
                   and the value may or not be quoted. Handle all 4 cases.
                */
                if ((memcmp (buf, "imagename", 9) == 0) && ((buf[9] == ':') || (buf[9] == '=')))
                {
                    s = (buf[10] == '"') ? &buf[11] : &buf[10];

                    while (1)
                    {
                        int inch = s[len];

                        if ((inch == '"') || (inch == '\n') || (inch == 0))
                        {
                            break;
                        }

                        len++;
                    }

                    break;
                }
            }

            fclose (fp);
        }

        if (len >= sizeof(name))
        {
            len = sizeof(name) - 1;
        }

        memcpy (name, s, len);
        name[len] = 0;
    }

    if (name[0] != 0)
    {
        size_t len = strlen(name);

        if (len >= maxSize)
        {
            len = maxSize - 1;
        }

        memcpy (pValue, name, len);
        pValue[len] = 0;

        return 0;
    }

    pValue[0] = 0;

    return -1;
}

/**
 * Identify Device model
 */
static device_model_t check_model(void)
{
    char line[128];

    if (GetFirmwareName(line, sizeof(line)) == 0)
    {
        LOGINFO("Version: %s", line);

        if (strstr(line,"WNXL11BWL")) {
            return MODEL_WNXL11BWL;
        }
        if (strstr(line, "SIM")) {
            return MODEL_SIMULATED;
        }
        if (strstr(line, "CGM4331COM")) {
            return MODEL_CGM4331COM;
        }
        if (strstr(line, "TG4482PC2")) {
            return MODEL_TG4482PC2;
        }
    }

    return MODEL_UNKNOWN;
}

/**
 * Validate that the string passed in valid IPv4 format xxx.xxx.xxx.xxx
 *
 * @param[in]   ipv4    String to be validated
 */
static bool validate_ipv4(char* ipv4) {
    struct sockaddr_in sa;

    int result = inet_pton(AF_INET, ipv4, &(sa.sin_addr));
    if (result <= 0) {
        LOGERROR("Invalid IP - %s\n", ipv4);
        return false;
    }

    return true;
}

/**
 * Execute commands and return results
 *
 * @param[in]   cmd     Command to be executed
 * @param[out]  out     Execution output
 * @param[in]   out_sz  Buffer size of the out parameter. Execution output will be clipped if the command output is
 *                      larger that out_sz.
 * @return Returns the return value of executed command.
 */
static int cmd_exec(char *cmd, char *out, size_t out_sz) {
    FILE        *fp;
    char        buf[BUF_SIZE];
    size_t      total_read = 0;

    fp = popen(cmd, "r");
    if (!fp) {
        LOGERROR("%s - popen failed, errno = %d\n", cmd, errno);
        return errno;
    }

    // TODO: Exceeded buffer size failure is seen when passing the exact required out_sz sizes like BUF_IF_NAME,
    // BUF_IPV4, BUF_MAC etc. Worked around it for now by using large out_sz, but come back later and figure out why
    // the issue was happening.
    memset(out, 0, out_sz);
    while (fgets(buf, BUF_SIZE, fp) != NULL) {
        size_t len = strlen(buf);
        if (total_read + len >= out_sz) {
            LOGERROR("Exceeded buffer size, clipping output\n");
            break;
        }
        /*CID 337463 The destination of a strcpy call must have enough space to accept the source.*/
        strncpy(out + total_read, buf, out_sz - total_read - 1);
        total_read += len;
    }

    while(out[strlen(out)-1] == '\r' || out[strlen(out)-1] == '\n') {
        out[strlen(out)-1] = '\0';
    }

    return pclose(fp);
}

/**
 * Pings destination URL or IP address to confirm connectivity.
 *
 * @param[in]   dest    Destination IP address or URL
 * @param[in]   iface   Optionally pass in the interface if you need to ping through any specific interface.
 *                      To use defaul interface, pass in NULL
 * @param[in]   desc    Optionally provide description of the interface for logging. If NULL passed in, use value of
 *                      dest for logging.
 */
static bool cmd_ping(char* dest, char* iface, char* desc) {
    char cmd[256];
    char buf[1024];

    if (iface) {
        snprintf(cmd, sizeof(cmd), "ping -c 1 -I %s %s", iface, dest);
    } else {
        snprintf(cmd, sizeof(cmd), "ping -c 1 %s", dest);
    }

    if (cmd_exec(cmd, buf, sizeof(buf))) {
        LOGERROR("%s is not reachable via %s interface\n", desc ? desc : dest, iface ? iface : "default");
        return false;
    } else {
        LOGSUCCESS("%s is reachable via %s interface\n", desc ? desc : dest, iface ? iface : "default");
        return true;
    }
}

/**
 * Pings any random root server to confirm internet connectivity.
 *
 * @param[in]   iface   Optionally pass in the interface if you need to ping through any specific interface.
 *                      To use defaul interface, pass in NULL
 */
static bool cmd_ping_root_serv(char* iface) {
    int r;
    int trials=2;
    int cnt_serv = sizeof(g_root_servers)/sizeof(g_root_servers[0]);

    LOGINFO("Checking internet connectivity over %s interface\n", iface ? iface : "default");
    while (trials--) {
        r = generate_random() % cnt_serv;
        if (cmd_ping(g_root_servers[r], iface, NULL)) {
            return true;
        }
        LOGINFO("Attempting to direcly ping %s root server IP %s\n", g_root_servers[r], g_root_servers_ipv4[r]);
        if (cmd_ping(g_root_servers_ipv4[r], iface, NULL)) {
            return true;
        }
        LOGINFO("%d attempts remaining\n", trials);
    }
    LOGERROR("Internet connectivity check over %s interface failed\n", iface ? iface : "default");
    return false;
}

/**
 * Identify the IP default route
 *
 * @param[out]  default_route   Default route for the device
 */
static bool check_default_route(char* default_route) {
    char cmd[64];

    if (default_route == NULL) {
        LOGERROR("NULL argument(s) passed to %s\n", __func__);
        return false;
    }

    // Find default route interface
    snprintf(cmd, sizeof(cmd), "ip route show default | cut -d' ' -f5");
    cmd_exec(cmd, default_route, BUF_IF_NAME);
    if (!strlen(default_route)) {
        LOGERROR("Could not get default route\n");
        return false;
    }

    LOGINFO("Default route is through  %s\n", default_route);
    return true;
}

/**
 * Execute all commands passed in and print results.
 *
 * @param[in]   commands    Array of commands, where each command is a key value pair {"description", "commands"}
 * @param[in]   num_cmds    Number of commands
 */
static void xmesh_print_dumps(commands_t *commands, int num_cmds) {
    /*CID 337459 stack_use_local_overflow Local variable buf uses 32768 bytes of stack space, which exceeds the maximum single use of 10000 bytes.*/
    char* buf = malloc(MAX_BUFFER_SIZE);
    if (buf == NULL)
    {
       LOGDUMPERROR("Memory allocation failed for buf\n");
       return;
    }
    commands_t command;
    int i;

    for (i=0; i<num_cmds; i++) {
        command = *(commands+i);
        if (cmd_exec(command.cmd, buf, sizeof(buf))) {
            LOGDUMPERROR("command failed \"%s\"\n",command.cmd);
            continue;
        }
        LOGDUMPINFO("%s%s\n",command.desc,buf);
    }
    free(buf);
}

// =================== XLE Diagnostics APIs =================== //

/**
 * Add all additional dumps required from XLE as key value pairs using the format {"description", "command"}
 */
static void xmesh_xle_dumps() {
    LOGINFO("================== MESH DIAGNOSTIC TOOL | XLE | DUMPS ==================\n");
    commands_t commands[] = {
        {"Version           : ", "sed -n 's/^imagename[:=]\"\\?\\([^\"]*\\)\"\\?/\\1/p' /version.txt"},
        {"Uptime            : ", "uptime"},
        {"Load Average      : ", "cat /proc/loadavg"},
        {"CPU               :\n", "mpstat"},
        {"Memory            :\n", "cat /proc/meminfo | grep \"MemTotal\\|MemFree\\|MemAvailable\""},
        {"wl0 Interface     :\n", "ifconfig wl0"},
        {"wl0 status        :\n", "wl -i wl0 status"},
        {"wl1 interface     :\n", "ifconfig wl1"},
        {"wl1 status        :\n", "wl -i wl1 status"},
        {"wl2 interface     :\n", "ifconfig wl2"},
        {"wl2 status        :\n", "wl -i wl2 status"},
        {"Wifi_VIF_State    :\n", "/usr/opensync/tools/ovsh s Wifi_VIF_State"},
        {"Wifi_Inet_State   :\n", "/usr/opensync/tools/ovsh s Wifi_Inet_State"},
        {"Wifi_Inet_Config  :\n", "/usr/opensync/tools/ovsh s Wifi_Inet_Config -w if_type==vif"},
        {"Wifi_Master_State :\n", "/usr/opensync/tools/ovsh s Wifi_Master_State"},
        {"Connection_Manager_Uplink :\n", "/usr/opensync/tools/ovsh s Connection_Manager_Uplink"},
        {"AWLAN_Node        :\n", "/usr/opensync/tools/ovsh s AWLAN_Node"},
        {"Manager           :\n", "/usr/opensync/tools/ovsh s Manager"},
        {"ip routes         :\n", "ip route show"},
        {"ovs switch        :\n", "ovs-vsctl show"},
        {"brWAN interface   :\n", "ifconfig brWAN"},
        {"wwan0 interface   :\n", "ifconfig wwan0"},
        {"wwan0 iptables    :\n", "iptables-save | grep wwan0"}
    };

    xmesh_print_dumps(commands,sizeof(commands)/sizeof(commands_t));
    LOGINFO("========================================================================\n");
    return;
}

/**
 * Check the active backhaul interface.
 *
 * Backhaul interface is identified from Connection_Manager_Uplink table
 * Works for both WiFi and ethernet backhauls
 *
 * @param[out]  sta returns the active backhaul interface name
 */
static bool xle_get_backhaul_sta(char* sta) {
    char cmd[256];
    char buf[64];
    char *ethx;
    char temp[BUF_IF_NAME];
    errno_t rc = -1;

    if (sta == NULL) {
        LOGERROR("NULL argument(s) passed to %s\n", __func__);
        return false;
    }
    memset(sta,0,BUF_IF_NAME);

    // Check the backhaul interface reported by Connection_Manager_Uplink table
    snprintf(cmd, sizeof(cmd), "/usr/opensync/tools/ovsh -r s Connection_Manager_Uplink -w is_used==true if_name");
    cmd_exec(cmd,buf,sizeof(buf));
    /*CID 337461  sscanf assumes an arbitrarily long string, callers must use correct precision specifiers or never use sscanf.*/
    if (!strlen(buf) || sscanf(buf, "g-%15s", sta) <= 0) {
        LOGERROR("Connection_Manager_Uplink does not indicate any valid backhaul interface \"%s\"\n", sta);
        return false;
    }
    LOGINFO("Backhaul interface as per Connection_Manager_Uplink table is \"%s\"\n", sta);

    // Verify the interface reported by Connection_Manager_Uplink is actually active
    if (strstr(sta, "wl")) {
        snprintf(cmd, sizeof(cmd), "wl -i %s bssid 2>/dev/null", sta);
        cmd_exec(cmd, buf, sizeof(buf));
        if (strlen(buf)) {
            LOGSUCCESS("XLE is connected via %s - backhaul bssid %s\n", sta, buf);
            return true;
        }
    } else if (strstr(sta, "eth")) {
        rc = strcpy_s(temp, BUF_IF_NAME, sta);
        ERR_CHK(rc);
        ethx = strtok(temp, ".");
        snprintf(cmd, sizeof(cmd), "cat /sys/class/net/%s/carrier", ethx);
        cmd_exec(cmd, buf, sizeof(buf));
        if (strlen(buf) && !strcmp(buf, "1")) {
            LOGSUCCESS("XLE is connected via ethernet interface %s\n", sta);
            return true;
        }
    }

    LOGERROR("Backhaul connection is not currently active over interface %s\n", sta);
    return false;
}

/**
 * Get the backhaul interface local IP
 *
 * @param[in]   sta             Active backhaul interface name
 * @param[out]  sta_bhaul_ip    XLE backhaul interface IP
 */
static bool xle_get_backhaul_ip(char* sta, char* sta_bhaul_ip) {
    char cmd[256];
    char buf[BUF_IPV4];
    errno_t rc = -1;

    if (sta_bhaul_ip == NULL || sta == NULL) {
        LOGERROR("NULL argument(s) passed to %s\n", __func__);
        return false;
    }

    memset(sta_bhaul_ip,0,BUF_IPV4);
    // Find IP of backhaul interface
    snprintf(cmd,sizeof(cmd),"ip addr show %s | grep \"inet\\b\" | awk '{print $2}' | cut -d/ -f1", sta);
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("XLE has no backhaul IP on %s\n", sta);
        return false;
    }

    rc = strcpy_s(sta_bhaul_ip, BUF_IPV4, buf);
    ERR_CHK(rc);

    if (!validate_ipv4(sta_bhaul_ip)) {
        LOGERROR("Invalid backhaul IP received - %s\n", sta_bhaul_ip);
        return false;
    }

    LOGSUCCESS("XLE has backhaul IP %s on %s\n", sta_bhaul_ip, sta);
    return true;
}

/**
 * Verify gretap local and remote IPs are valid
 *
 * @param[in]   sta             Active backhaul interface name
 * @param[in]   sta_bhaul_ip    XLE backhaul interface IP
 */
static bool xle_validate_gretap_endpoints(char* sta, char* sta_bhaul_ip) {
    char cmd[256];
    char buf[BUF_IPV4];

    if (sta_bhaul_ip == NULL || sta == NULL) {
        LOGERROR("NULL argument(s) passed to %s\n", __func__);
        return false;
    }

    // Find gretap local ip
    snprintf(cmd,sizeof(cmd),"ip -d -4 link show g-%s | grep gretap | cut -d' ' -f9",sta);
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("XLE does not have the required GRE\n");
        return false;
    }
    if (strncmp(buf, sta_bhaul_ip, BUF_IPV4)) {
        LOGERROR("gretap local IP %s does not match the backhaul IP %s\n", buf, sta_bhaul_ip);
        return false;
    }

    // Find gretap remote ip
    snprintf(cmd,sizeof(cmd),"ip -d -4 link show g-%s | grep gretap | cut -d' ' -f7",sta);
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("Could not parse gretap remote IP\n");
        return false;
    }
    if (!validate_ipv4(buf)) {
        LOGERROR("Invalid gretap remote IP received - %s\n", buf);
        return false;
    }
    LOGSUCCESS("gretap remote IP received - %s\n", buf);

    if (!cmd_ping(buf, NULL, "gretap remote IP")){
        return false;
    }

    LOGSUCCESS("gretap has been created with the right endpoints\n");
    return true;
}

/**
 * Verify that XLE default route is 192.168.245.254 and main gateway is reachable from XLE
 */
static bool xle_validate_mgw_conn() {
    char cmd[256];
    char buf[64];

    snprintf(cmd,sizeof(cmd),"ip route show default | grep 192.168.245.254");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("Default route is not set properly\n");
        return false;
    }
    LOGSUCCESS("Default route is set to 192.168.245.254\n");

    if (!cmd_ping("192.168.245.254", NULL, "Main gateway")) {
        return false;
    }

    return true;
}

/**
 * Verify br-home configuration
 *
 * br-home interface should contain the GRE port g-xxx (g-wl0, g-eth0.123, ...)
 * br-home interface should have a valid IP
 *
 * @param[in]   sta Active backhaul interface name
 */
static bool xle_validate_brhome(char* sta) {
    char cmd[256];
    char buf[64];

    if (sta == NULL) {
        LOGERROR("NULL argument(s) passed to %s\n", __func__);
        return false;
    }

    snprintf(cmd,sizeof(cmd),"ovs-vsctl list-ports br-home | grep g-%s", sta);
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("br-home bridge does not contain port g-%s\n", sta);
        return false;
    }
    LOGSUCCESS("br-home bridge includes port g-%s\n", sta);

    snprintf(cmd,sizeof(cmd),"ip addr show br-home | grep \"inet\\b\" | awk '{print $2}' | cut -d/ -f1");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("br-home does not have a valid IP\n");
        return false;
    }
    if (!validate_ipv4(buf)) {
        LOGERROR("br-home IP is not valid %s\n",buf);
        return false;
    }
    LOGSUCCESS("br-home has valid IP %s\n", buf);

    return true;
}

/**
 * Verify brWAN configuration
 *
 * Verify brWAN has been assigned a valid IP address
 * Verify brWAN has g-xxx.200 vlan port
 *
 * @param[in]   sta Active backhaul interface name
 */
static bool xle_validate_brwan(char* sta) {
    char cmd[256];
    char buf[1024];
    char temp[BUF_IF_NAME];
    char port[BUF_IF_NAME+6];
    errno_t rc = -1;

    if (sta == NULL) {
        LOGERROR("NULL argument(s) passed to %s\n", __func__);
        return false;
    }

    snprintf(cmd,sizeof(cmd),"ifconfig brWAN | grep \"inet addr\" | cut -d':' -f2 | cut -d' ' -f1");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("brWAN does not have an IP yet\n");
        g_count.xle_brwan_no_ip++;
        return false;
    }
    if (!validate_ipv4(buf)) {
        LOGERROR("brWAN IP is not valid %s\n",buf);
        return false;
    }
    LOGSUCCESS("brWAN has valid IP %s\n", buf);

    if (strstr(sta, "eth")) {
        rc = strcpy_s(temp, BUF_IF_NAME, sta);
        ERR_CHK(rc);
        strtok(temp, ".");
        snprintf(port, sizeof(port), "%s.200", temp);
    } else {
        snprintf(port, sizeof(port), "g-%s.200", sta);
    }
    snprintf(cmd,sizeof(cmd),"ovs-vsctl list-ports brWAN | grep %s", port);
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("brWAN bridge does not contain port g-%s.200\n", sta);
        g_count.xle_brwan_no_gre++;
        return false;
    }
    LOGSUCCESS("brWAN bridge includes port g-%s.200\n", sta);

    return true;
}

/**
 * Verify XLE's LTE interface has received an IP and ping to external IP works via LTE.
 */
static bool xle_validate_wwan0() {
    char cmd[256];
    char buf[64];

    snprintf(cmd,sizeof(cmd),"ifconfig wwan0 | grep \"inet addr\" | cut -d':' -f2 | cut -d' ' -f1");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("wwan0 does not have an IP yet\n");
        return false;
    }
    LOGSUCCESS("wwan0 has IP %s\n", buf);

    // Check cellular environment status
    snprintf(cmd,sizeof(cmd),"dmcli eRT getv Device.Cellular.Interface.1.X_RDK_RadioEnvConditions | grep 'value:' | cut -d':' -f3 | xargs");
    cmd_exec(cmd, buf, sizeof(buf));
    if (strlen(buf)) {
        LOGINFO("Cellular radio environment condition : %s\n", buf);
    }

    if (!cmd_ping_root_serv("wwan0")) {
        return false;
    }

    return true;
}

/**
 * Verify XB's brRWAN IP is visible in the XLE's arp list, and verify ping works if device is in wan failover mode
 *
 * @param[in]   wfo     Should be set to true if the device is in wan failover mode
 */
static bool xle_check_brrwan_conn(bool wfo) {
    char cmd[256];
    char buf[1024];
    char* token;
    bool ret = false;

    // Get XB brRWAN IP
    snprintf(cmd,sizeof(cmd),"arp -a | grep -w ether | grep -w brWAN | cut -d'(' -f2 | cut -d')' -f1");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("Cannot find gateway's remote wan IP\n");
        return false;
    }

    // If XB reboots, we are seeing multiple IPs and MACs in the arp list for brWAN interface.
    // Active IP can only be found by looping through all options.
    if (strlen(buf) > BUF_IPV4) {
        LOGINFO("Looks like we might have multiple IPs from arp list on brWAN interface\n%s\n", buf);
        token = strtok(buf, "\n");
        while ( token != NULL ) {
            if (validate_ipv4(token)) {
                LOGINFO("Detected potential candidate for gateway's remote wan IP %s\n", token);
                ret = true; // atleast one valid IP found, so return true in case of non wfo case
                if (wfo && cmd_ping(token, NULL, NULL)) {
                    return true;
                }
            }
            token = strtok(NULL, "\n");
        }
        if (wfo) {
            LOGERROR("Could not ping any of the IPs associated with brWAN\n");
            return false;
        }
    } else {
        if (!validate_ipv4(buf)) {
            LOGERROR("Invalid IP for gateway's remote wan IP - %s\n", buf);
            return false;
        }

        LOGSUCCESS("Detected gateway's remote wan IP %s\n", buf);
        ret = true; 

        if (wfo && !cmd_ping(buf, NULL, NULL)) {
            return false;
        }
    }

    return ret;
}

static bool xle_check_wfo_mode(bool wfo) {
    char cmd[256];
    char buf[512];

    snprintf(cmd,sizeof(cmd),"sysevent get mesh_wfo_enabled");
    cmd_exec(cmd,buf,sizeof(buf));
    LOGINFO("mesh_wfo_enabled : %s\n", strlen(buf) ? buf : "false");

    if(wfo) {
        if (strncmp(buf, "true", 5)) {
            LOGERROR("XLE is not in wan failover mode\n");
            g_count.not_wfo++;
            return false;
        }
        LOGSUCCESS("XLE is currently in wan failover mode\n");
        snprintf(cmd,sizeof(cmd),"mpstat");
        cmd_exec(cmd, buf, sizeof(buf));
        if (strlen(buf)) {
            LOGINFO("CPU usage:\n%s\n", buf);
        }
    }
    return true;
}

/**
 * Run diagnostics on XLE
 *
 * 1. Check currently connected backhaul Interface
 * 2. Get the backhaul interface IP
 * 3. Verify gretap local and remote interfaces are valid
 * 4. Verify br-home configuration
 * 5. Verify brWAN configuration
 * 6. Verify default route and connectivity with main gateway
 * 7. Verify XB's remote wan IP is visible and reachable in case of WFO
 * 8. Verify LTE interface is up and able to connect to Internet
 * 9. Verify XLE is able to connect to internet over default route
 *
 * @param[in]   wfo     Should be set to true if the device is in wan failover mode
 */
static void xmesh_xle(bool wfo) {
    char sta[BUF_IF_NAME];
    char sta_bhaul_ip[BUF_IPV4];
    bool all_good = true;

    LOGINFO("====================== MESH DIAGNOSTIC TOOL | XLE ======================\n");

    if (!xle_check_wfo_mode(wfo)) {
        all_good = false;
    }

    if (!xle_get_backhaul_sta(sta)){
        g_count.xle_bhaul_no_conn++;
        all_good = false;
        goto results;
    }

    if (!xle_get_backhaul_ip(sta, sta_bhaul_ip)) {
        g_count.xle_bhaul_no_ip++;
        all_good = false;
        goto results;
    }

    if (!xle_validate_gretap_endpoints(sta, sta_bhaul_ip)) {
        g_count.xle_gre_remote_unreach++;
        all_good = false;
        goto results;
    }

    if (!xle_validate_brhome(sta)) {
        g_count.xle_brhome_error++;
        all_good = false;
        goto results;
    }

    if (!xle_validate_brwan(sta)) {
        all_good = false;
        goto results;
    }

    if (!xle_validate_mgw_conn()) {
        g_count.xle_mgw_unreachable++;
        all_good = false;
        goto results;
    }

    if (!xle_check_brrwan_conn(wfo)) {
        g_count.xle_brrwan_conn_fail++;
        all_good = false;
    }

    if (!xle_validate_wwan0()) {
        g_count.xle_wwan0_offline++;
        all_good = false;
    }

    if (!cmd_ping_root_serv(NULL)) {
        g_count.no_internet++;
        all_good = false;
        goto results;
    }

results:
    if (all_good) {
        LOGSUCCESS("Everything on XLE looks good\n");
        g_count.count_all_good++;
    } else {
        LOGERROR("Encountered errors during execution. Printing debugging dumps to %s\n", LOG_FILE_BBOXDMP);

        commands_t commands[] = {
            {"AccountID         : " , "dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AccountInfo.AccountID | grep -w 'value:' | cut -d':' -f3 | xargs"},
            {"udhcpc process    :\n", "ps -ww | grep udhcp | grep -v grep"},
            {"Wifi_Inet_Config - GRE :\n", "/usr/opensync/tools/ovsh s Wifi_Inet_Config -w if_type==gre"},
            {"IP Routes         :\n", "ip route show" },
            {"GRE IP Links      :\n", "ip -d link show | grep ': g-' -A3" },
            {"ovs-vsctl show    :\n", "ovs-vsctl show"},
            {"ovs-ofctl show brWAN :\n", "ovs-ofctl show brWAN"},
            {"ovs-appctl fdb/show br-home", "ovs-appctl fdb/show br-home"},
            {"dnsmasq process   :\n", "ps -ww | grep dnsmasq | grep -v grep"},
            {"dnsmasq.conf interfaces :\n", "cat /var/dnsmasq.conf | grep 'interface=' | cut -d'=' -f2"}
        };
        xmesh_print_dumps(commands,sizeof(commands)/sizeof(commands_t));
    }

    LOGINFO("========================================================================\n");
}

// =================== XB Diagnostics APIs ==================== //

/**
 * Add all additional dumps required from XB as key value pairs using the format {"description", "command"}
 */
static void xmesh_xb_dumps() {
    LOGINFO("================== MESH DIAGNOSTIC TOOL | XB | DUMPS ===================\n");
    commands_t commands[] = {
        {"Version           : ",  "sed -n 's/^imagename[:=]\"\\?\\([^\"]*\\)\"\\?/\\1/p' /version.txt"},
        {"Uptime            : ",  "uptime"},
        {"Load Average      : ",  "cat /proc/loadavg"},
        {"Default IP route  : ",  "ip route show default"},
        {"CPU               :\n", "mpstat"},
        {"Memory            :\n", "cat /proc/meminfo | grep \"MemTotal\\|MemFree\\|MemAvailable\""},
        {"AWLAN Node        :\n", "/usr/opensync/tools/ovsh s AWLAN_Node"},
        {"Manager           :\n", "/usr/opensync/tools/ovsh s Manager"},
        {"VIF Config        :\n", "/usr/opensync/tools/ovsh s Wifi_VIF_Config if_name mac_list mac_list_type ssid security enabled"},
        {"VIF State         :\n", "/usr/opensync/tools/ovsh s Wifi_VIF_State  if_name mac_list mac_list_type ssid security enabled"},
        {"Wifi_Inet_Config  :\n", "/usr/opensync/tools/ovsh s Wifi_Inet_Config -w if_type==gre"},
        {"Wifi_Associated_Clients :\n", "/usr/opensync/tools/ovsh s Wifi_Associated_Clients"},
        {"DHCP_leased_IP    :\n", "/usr/opensync/tools/ovsh s DHCP_leased_IP"},
        {"ovs-vsctl show    :\n", "ovs-vsctl show"},
        {"ifconfig brRWAN   :\n", "ifconfig brRWAN"}
    };

    xmesh_print_dumps(commands, sizeof(commands)/sizeof(commands_t));
    LOGINFO("========================================================================\n");
    return;
}

/**
 * Find all pods connected to the XB directly
 *
 * @param[out]  conn_pods_list  Pointer to the array of BSSIDs of pods connected to XB on backhaul interfaces
 */
static int xb_find_connected_pods(char ***conn_pods_list) {
    char cmd[256];
    char buf[32];
    int total_pods = 0;
    int pods_on_iface;
    int ifnum;
    int i;
    errno_t rc = -1;

    // Identify clients connected to backhaul accesspoints 13, 14
    for (ifnum=13; ifnum<=14; ifnum++) {
        snprintf(cmd,sizeof(cmd),"dmcli eRT getv Device.WiFi.AccessPoint.%d.AssociatedDeviceNumberOfEntries | grep value: | cut -d':' -f3 | xargs", ifnum);
        cmd_exec(cmd,buf,sizeof(buf));
        if (!strlen(buf)) {
            LOGERROR("Cannot fetch number of clients associated with accesspoint %d\n", ifnum);
            continue;
        }
        pods_on_iface = atoi(buf);
        LOGINFO("%d pods connected to Device.WiFi.AccessPoint.%d.\n", pods_on_iface, ifnum);
        if (pods_on_iface > 0) {
            for (i=1; i<=pods_on_iface; i++) {
                *conn_pods_list = (char**)realloc(*conn_pods_list, (total_pods+1) * sizeof(char*));
                (*conn_pods_list)[total_pods] = (char*)malloc(BUF_MAC);
                snprintf(cmd,sizeof(cmd),"dmcli eRT getv Device.WiFi.AccessPoint.%d.AssociatedDevice.%d.MACAddress | grep value: | rev | cut -d' ' -f2 | rev", ifnum, i);
                cmd_exec(cmd,buf,sizeof(buf));
                if (!strlen(buf)) {
                    LOGERROR("Cannot fetch Device.WiFi.AccessPoint.%d.AssociatedDevice.%d.MACAddress\n", ifnum, i);
                    continue;
                } else {
                    rc = strcpy_s((*conn_pods_list)[total_pods], BUF_MAC, buf);
                    ERR_CHK(rc);
                    LOGINFO("Pod %s is connected on accesspoint %d\n", (*conn_pods_list)[total_pods], ifnum);
                    total_pods++;
                }
            }
        }
    }

    return total_pods;
}

/**
 * Find the XLE IP from the dnsmasq.leases file
 *
 * Hostname for XLE in dnsmasq.leases expected to contain model name WNXL11BWL
 * Run all the connected pod bssids through the dnsmasq.leases file to verify if any connected pod is an XLE
 * Assumtion:  One location would only have at max one XLE
 *
 * @param[in]   conn_pods_list  List of pod BSSIDs connected to XB
 * @param[in]   num_pods        Number of pods connected to XB
 * @param[out]  xle_ip          IP of the XLE if found connected to the XB
 */
static bool xb_find_xle_ip(char** conn_pods_list, int num_pods, char* xle_ip) {
    char cmd[256];
    char buf[1024];
    int xle_id = -1;
    int i;

    snprintf(cmd, sizeof(cmd), "cat /nvram/dnsmasq.leases | grep WNXL11BWL | cut -d' ' -f2 | tr '\\n' ' '");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("dnsmasq.leases file does not have an entry for any XLE device\n");
        return false;
    }

    // Checking if any of the pods in the connected list is an XLE
    for (i=0; i<num_pods; i++) {
        if (strstr(buf, conn_pods_list[i])) {
            xle_id = i;
            break;
        }
    }

    if (xle_id < 0) {
        LOGERROR("None of the pods connected directly to XB backhaul is an XLE\n");
        return false;
    }

    // Find the link local IP of the XLE identified
    snprintf(cmd, sizeof(cmd), "cat /nvram/dnsmasq.leases | grep WNXL11BWL | grep %s | cut -d' ' -f3", conn_pods_list[xle_id]);
    cmd_exec(cmd, xle_ip, BUF_IPV4);
    if (!strlen(xle_ip)) {
        LOGERROR("Could not get XLE IP from dnsmasq.leases\n");
        return false;
    }

    if (!validate_ipv4(xle_ip)){
        LOGERROR("Error parsing XLE IP read from dnsmasq.leases - %s\n", xle_ip);
        return false;
    }

    LOGSUCCESS("Obtained associated XLE from dnsmasq.leases file IP:%s BSSID:%s\n", xle_ip, conn_pods_list[xle_id]);
    return true;
}

/**
 * Verify GRE tunnel interfaces on the XB connected to the XLE.
 *
 * Only applicable if the XLE is located one hop from the XB.
 * Identify the GRE interface name from Wifi_Inet_Config table
 * Verify the port is available under br403
 *
 * @param[in]   xle_ip IP of XLE connected to the XB
 */
static bool xb_validate_xle_gre_iface(char* xle_ip) {
    char cmd[256];
    char buf[1024];
    char pgd_name[BUF_IF_NAME];

    snprintf(cmd, sizeof(cmd), "/usr/opensync/tools/ovsh s Wifi_Inet_Config -w gre_remote_inet_addr==\"%s\" | grep if_name | cut -d\"|\" -f2 | sed 's/ //g'", xle_ip);
    cmd_exec(cmd, pgd_name, BUF_IF_NAME);
    if (!strlen(pgd_name)) {
        LOGERROR("GRE interface has not been inserted with the XLE's link local IP\n");
        g_count.xb_no_pgd++;
        return false;
    }

    LOGSUCCESS("GRE interface has been inserted - %s\n",pgd_name);

    snprintf(cmd, sizeof(cmd), "ip -d -4 link show %s", pgd_name);
    if (cmd_exec(cmd,buf,sizeof(buf))) {
        LOGERROR("WFO  Device \"%s\" does not exist\n", pgd_name);
        g_count.xb_no_dev_detected++;
        return false;
    }
    LOGINFO("GRE tunnel details\n%s\n",buf);

    snprintf(cmd, sizeof(cmd), "ovs-vsctl list-ports br403 | grep %s",pgd_name);
    cmd_exec(cmd,buf,sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("br403 bridge does not contain port %s\n",pgd_name);
        g_count.xb_pgd_not_in_br403++;
        return false;
    }
    LOGSUCCESS("br403 bridge includes port %s\n",pgd_name);

    // TODO check if pgdx-yy.200 vlan is up

    return true;
}

/**
 * Verify brRWAN got an IP and is pingable if the device is in wan fail over mode.
 *
 * @param[in]   wfo     Should be set to true if the device is in wan fail over mode
 */
static bool xb_validate_brrwan(bool wfo) {
    char cmd[256];
    char buf[32];

    snprintf(cmd,sizeof(cmd),"ifconfig brRWAN | grep 'inet addr' | cut -d':' -f2 | cut -d' ' -f1");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("brRWAN does not have an IP yet\n");
        g_count.xb_brrwan_no_ip++;
        return false;
    }
    LOGSUCCESS("brRWAN has IP %s\n", buf);

    if (wfo && !cmd_ping("192.168.246.1", NULL, "XLE brWAN")) {
        g_count.xb_brwan_unreach++;
        return false;
    }
    return true;
}

/**
 * Verify configurations set under Device.X_RDK_MeshAgent.MeshWANLink. is correct.
 */
static bool xb_check_meshwanlink_cfg() {
    char cmd[256];
    char buf[BUF_IF_NAME];
    bool ret = true;

    snprintf(cmd,sizeof(cmd),"dmcli eRT getv Device.X_RDK_MeshAgent.MeshWANLink.Interface.Name | grep value: | cut -d':' -f3 | xargs");
    cmd_exec(cmd, buf, sizeof(buf));
    LOGINFO("Device.X_RDK_MeshAgent.MeshWANLink.Interface.Name is set to \"%s\"\n", buf);
    if (strncmp(buf, "brRWAN", BUF_IF_NAME)) {
        LOGERROR("Incorrect configuration for Device.X_RDK_MeshAgent.MeshWANLink.Interface.Name\n");
        ret = false;
    }

    snprintf(cmd,sizeof(cmd),"dmcli eRT getv Device.X_RDK_MeshAgent.MeshWANLink.Status | grep value: | cut -d':' -f3 | xargs");
    cmd_exec(cmd, buf, sizeof(buf));
    LOGINFO("Device.X_RDK_MeshAgent.MeshWANLink.Status is set to \"%s\"\n", buf);
    if (strncmp(buf, "true", BUF_IF_NAME)) {
        LOGERROR("Incorrect configuration for Device.X_RDK_MeshAgent.MeshWANLink.Status\n");
        ret = false;
    }

    return ret;
}

static bool xb_check_wfo_mode(bool wfo) {
    char cmd[256];
    char buf[512];

    snprintf(cmd,sizeof(cmd),"dmcli eRT getv Device.X_RDK_WanManager.CurrentActiveInterface | grep value: | cut -d':' -f3 | xargs");
    cmd_exec(cmd, buf, sizeof(buf));
    if (!strlen(buf)) {
        LOGERROR("Could not get the current active interface\n");
        g_count.xb_no_actv_iface++;
        return false;
    }
    LOGINFO("Current active interface is \"%s\"\n", buf);

    if (wfo) {
        if (strncmp(buf, "brRWAN", BUF_IF_NAME)) {
            LOGERROR("XB is not in wan failover mode\n");
            g_count.not_wfo++;
            return false;
        }
        LOGSUCCESS("XB is currently in wan failover mode\n");
        snprintf(cmd,sizeof(cmd),"mpstat");
        cmd_exec(cmd, buf, sizeof(buf));
        if (strlen(buf)) {
            LOGINFO("CPU usage:\n%s\n",buf);
        }
    }
    return true;
}

/**
 * Run diagnostics on XB
 *
 * 1. Check TR181 configurations Device.X_RDK_MeshAgent.MeshWANLink.Interface.Name
 *                               Device.X_RDK_MeshAgent.MeshWANLink.Status
 * 2. Check if any pods are connected to XB, if no pods are connected fail diagnostics.
 * 3. Check if any connected pods is an XLE based on dnsmasq.leases entry data. In case none of the connected pod
 *    is an XLE, don't fail as XLE could be connected behind any other connected pod.
 * 4. If any XLE found, check ping to local ip, find the gre tunnels and verify its configurations etc.
 * 5. Verify brRWAN has IP, and verify ping to 192.168.246.1 works in WFO mode
 * 6. Check ping to root server via brRWAN works in WFO mode.
 * 7. Check default route in WFO mode
 * 8. Check ping to root server via default route works
 *
 * @param[in]   wfo     Should be set to true if the device is in wan failover mode
 */
static void xmesh_xb(bool wfo) {
    char xle_ip[BUF_IPV4];
    char def_route[BUF_IF_NAME];
    char **pods_connected = NULL;
    int num_pods;
    int i;
    bool all_good = true;

    LOGINFO("======================= MESH DIAGNOSTIC TOOL | XB ======================\n");

    if (!xb_check_wfo_mode(wfo)) {
        all_good = false;
    }

    if (!xb_check_meshwanlink_cfg()){
        g_count.xb_meshwanlink_bad++;
        all_good = false;
    }

    if ((num_pods = xb_find_connected_pods(&pods_connected)) == 0) {
        LOGERROR("No XLE/pods are connected to XB\n");
        g_count.xb_no_pods_connected++;
        all_good = false;
        goto results;
    }

    if (xb_find_xle_ip(pods_connected, num_pods, xle_ip)) {
        LOGINFO("XLE is one hop to XB with local IP %s\n", xle_ip);

        if (!cmd_ping(xle_ip, NULL, "XLE local IP")) {
            g_count.xb_xle_no_ip++;
            all_good = false;
        }

        if(!xb_validate_xle_gre_iface(xle_ip)) {
            all_good = false;
        }

    } else {
        LOGINFO("XLE might not be connected to XB directly, skipping GRE checks\n");
    }

    if (!xb_validate_brrwan(wfo)) {
        all_good = false;
        goto results;
    }

    if (wfo) {
        if (check_default_route(def_route)) {
            if(strncmp(def_route, "brRWAN", BUF_IF_NAME)) {
                LOGERROR("Default route is through %s and not brRWAN\n", def_route);
                g_count.xb_brrwan_not_default++;
                all_good = false;
                goto results;
            }
        } else {
            LOGERROR("Could not get default route\n");
            all_good = false;
        }

        if (!cmd_ping_root_serv("brRWAN")) {
            g_count.xb_no_internet_brrwan++;
            all_good = false;
            goto results;
        }
    }

    if (!cmd_ping_root_serv( NULL)) {
        g_count.no_internet++;
        all_good = false;
    }

results:
    if (all_good) {
        LOGSUCCESS("Everything on main gateway looks good\n");
        g_count.count_all_good++;
    } else {
        LOGERROR("Encountered errors during execution. Printing debugging dumps to %s\n", LOG_FILE_BBOXDMP);
        commands_t commands[] = {
            {"AccountID         : ",  "dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AccountInfo.AccountID | grep -w 'value:' | cut -d':' -f3 | xargs"},
            {"br403 Ports List  :\n", "ovs-vsctl list-ports br403"},
            {"Node_Config       :\n", "/usr/opensync/tools/ovsh s Node_Config"},
            {"DHCP_leased_IP    :\n", "/usr/opensync/tools/ovsh s DHCP_leased_IP"},
            {"Wifi_Inet_Config - GRE :\n", "/usr/opensync/tools/ovsh s Wifi_Inet_Config -w if_type==gre"},
            {"Wifi_Associated_Clients :\n", "/usr/opensync/tools/ovsh s Wifi_Associated_Clients"},
            {"Device.X_RDK_Remote.Device. :\n", "dmcli eRT getv Device.X_RDK_Remote.Device.; echo"}, //dmcli working scenario return status is 1, instead
            {"Device.X_RDK_Connection :\n", "dmcli eRT getv Device.X_RDK_Connection.; echo"}         //of zero. Added a dummy echo at the end as a hack
        };
        xmesh_print_dumps(commands,sizeof(commands)/sizeof(commands_t));
    }

    LOGINFO("========================================================================\n");

    for (i=0; i<num_pods; i++) {
        if (pods_connected[i])
            free(pods_connected[i]);
    }
    if (pods_connected)
        free(pods_connected);
}

// ============================================================= //

static void* start_diagnostics(void* _args) {
    diag_args_t *diag_args = (diag_args_t *)_args;
    char uptime[128];

    if (diag_args->delay > 0) {
        LOGINFO("Delayed diagnostics enabled. Waiting %d seconds.\n", diag_args->delay);
        sleep(diag_args->delay);
    }

    while (g_xmesh_active) {
        cmd_exec("uptime", uptime, sizeof(uptime));
        LOGINFO("uptime -%s\n", uptime);
        pthread_mutex_lock(&xmesh_mutex);
        switch(diag_args->model) {
            case MODEL_SIMULATED:
            case MODEL_WNXL11BWL:
                if(diag_args->dumps_enabled)
                    xmesh_xle_dumps();
                xmesh_xle(diag_args->wfo);
                break;
            case MODEL_CGM4331COM:
            case MODEL_TG4482PC2:
                if(diag_args->dumps_enabled)
                    xmesh_xb_dumps();
                xmesh_xb(diag_args->wfo);
                break;
            default:
                LOGINFO("Diagnostics is not supported in this device\n");
        }
        g_count.total_iter++;
        pthread_mutex_unlock(&xmesh_mutex);

        sleep(diag_args->interval);
    }
    return NULL;
}

/**
 * Start a new mesh diagnostics session thread. Will not start a new
 * session if already one session is in progress.
 *
 * @param[in]   interval        Time in seconds between each diagnostics iterations.
 * @param[in]   dumps_enabled   Specifies whether to print all debug dumps or just print the diagnostics execution
 *                               results.
 * @param[in]   wfo             Set this value to true to run WFO specific checks in the XB / XLE
 * @param[in]   delay           Delay initialization of diagnostics run
 */
void xmesh_diag_start(int interval, bool dumps_enabled, bool wfo, int delay) {

    static diag_args_t diag_args;
    diag_args.interval = interval;
    diag_args.dumps_enabled = dumps_enabled;
    diag_args.wfo = wfo;
    diag_args.delay = delay;
    diag_args.model = check_model();

    if (g_xmesh_active) {
        LOGINFO("Diagnostics session already in progress, close existing session before starting new\n");
        return;
    }

    LOGINFO("Iteration interval : %d\n",diag_args.interval);
    LOGINFO("Dumps enabled      : %s\n",diag_args.dumps_enabled ? "true" : "false");
    LOGINFO("WFO diag enabled   : %s\n",diag_args.wfo ? "true" : "false");
    LOGINFO("Delayed start      : %d\n",diag_args.delay);
    g_xmesh_active = true;
    clock_gettime(CLOCK_MONOTONIC_RAW, &g_start_time);
    memset(&g_count, 0, sizeof(g_count));
    pthread_create(&xmesh_tid, NULL, start_diagnostics, &diag_args);
}

/**
 * Stops active mesh diagnostics session thread, and prints aggregated
 * diagnostics execution results from the session.
 */
void xmesh_diag_stop() {
    // Adding mutex lock to ensure session is not canceled in the middle of execution.
    pthread_mutex_lock(&xmesh_mutex);
    pthread_cancel(xmesh_tid);
    pthread_mutex_unlock(&xmesh_mutex);
    pthread_join(xmesh_tid,NULL);
    g_xmesh_active = false;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    time_t session_duration = now.tv_sec - g_start_time.tv_sec;

    LOGINFO("================== MESH DIAGNOSTIC TOOL OVERALL STATS ==================\n");
    LOGINFO("Session total duration (in seconds) : %ld\n", session_duration);
    LOGINFO("Total number of iterations : %d\n",g_count.total_iter);
    LOGINFO("Total number of successful iterations : %d\n",g_count.count_all_good);
    if(g_count.not_wfo)                 LOGERROR("Failure: Device is not in WFO mode                    : %d\n",g_count.not_wfo);
    if(g_count.xb_no_actv_iface)        LOGERROR("Failure: Could not fetch current active interface     : %d\n",g_count.xb_no_actv_iface);
    if(g_count.xb_meshwanlink_bad)      LOGERROR("Failure: MeshWANLink parameters are incorrect         : %d\n",g_count.xb_meshwanlink_bad);
    if(g_count.xb_no_pods_connected)    LOGERROR("Failure: No pods are connected to XB                  : %d\n",g_count.xb_no_pods_connected);
    if(g_count.xb_xle_no_ip)            LOGERROR("Failure: XLE's link local IP is not reachable         : %d\n",g_count.xb_xle_no_ip);
    if(g_count.xb_no_pgd)               LOGERROR("Failure: GRE interface not inserted with XLE local IP : %d\n",g_count.xb_no_pgd);
    if(g_count.xb_no_dev_detected)      LOGERROR("Failure: Device not detected in ip link               : %d\n",g_count.xb_no_dev_detected);
    if(g_count.xb_pgd_not_in_br403)     LOGERROR("Failure: pgd not present in br403                     : %d\n",g_count.xb_pgd_not_in_br403);
    if(g_count.xb_brrwan_no_ip)         LOGERROR("Failure: brRWAN has no IP                             : %d\n",g_count.xb_brrwan_no_ip);
    if(g_count.xb_brwan_unreach)        LOGERROR("Failure: brWAN 192.168.246.1 unreachable              : %d\n",g_count.xb_brwan_unreach);
    if(g_count.xb_brrwan_not_default)   LOGERROR("Failure: XB default route is not brRWAN               : %d\n",g_count.xb_brrwan_not_default);
    if(g_count.xb_no_internet_brrwan)   LOGERROR("Failure: Internet is unavailable via brRWAN           : %d\n",g_count.xb_no_internet_brrwan);
    if(g_count.xle_bhaul_no_conn)       LOGERROR("Failure: None of the backhaul interfaces are connected: %d\n",g_count.xle_bhaul_no_conn);
    if(g_count.xle_bhaul_no_ip)         LOGERROR("Failure: XLE has no backhaul IP yet                   : %d\n",g_count.xle_bhaul_no_ip);
    if(g_count.xle_gre_remote_unreach)  LOGERROR("Failure: Gateway unreachable in gre endpoint          : %d\n",g_count.xle_gre_remote_unreach);
    if(g_count.xle_brhome_error)        LOGERROR("Failure: br-home does not have valid IP or port       : %d\n",g_count.xle_brhome_error);
    if(g_count.xle_brwan_no_ip)         LOGERROR("Failure: brWAN does not have IP                       : %d\n",g_count.xle_brwan_no_ip);
    if(g_count.xle_brwan_no_gre)        LOGERROR("Failure: brWAN does not have GRE port                 : %d\n",g_count.xle_brwan_no_gre);
    if(g_count.xle_mgw_unreachable)     LOGERROR("Failure: Main gateway is unreachable                  : %d\n",g_count.xle_mgw_unreachable);
    if(g_count.xle_brrwan_conn_fail)    LOGERROR("Failure: Unable to connect with GW remote wan         : %d\n",g_count.xle_brrwan_conn_fail);
    if(g_count.xle_wwan0_offline)       LOGERROR("Failure: wwan0 is offline                             : %d\n",g_count.xle_wwan0_offline);
    if(g_count.no_internet)             LOGERROR("Failure: Internet is unavailable                      : %d\n",g_count.no_internet);
    LOGINFO("========================================================================\n");
}
