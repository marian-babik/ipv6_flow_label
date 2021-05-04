#ifndef __UTIL_H
#define __UTIL_H

#include <netinet/ip6.h>
#include <netdb.h>
#include <netinet/in.h>

#ifdef __UTIL_C
#define EXTERN
#else
#define EXTERN extern
#endif

#define MAX_MSG_LEN 100

typedef struct
{
    uint16_t port;
    uint16_t vrf;
    uint8_t flags;
    uint8_t reserved[3];
    uint8_t addr8[16];
} dst_opt_tlv_data_t;

typedef struct
{
    uint8_t padn;
    uint8_t len;
    uint8_t data[8];
} dst_opt_tlv_pad_t;

typedef struct
{
    dst_opt_tlv_data_t data;
    dst_opt_tlv_pad_t pad;
} dst_opt_tlv_t;

EXTERN void print_error(const char *const);
EXTERN void print_error_h(const char *const);
EXTERN void print_error_n(const char *const);
EXTERN int add_dstopts(int);
EXTERN void get_dst_opts(int);
EXTERN void *prepare_buff(u_int8_t, const void *const, size_t, size_t *);
EXTERN void print_hex_data(const unsigned char *const, const int);
EXTERN void find_option_data(dst_opt_tlv_t *, void *, uint8_t);
EXTERN void print_option_data(const dst_opt_tlv_t *const);
#endif
