#define __UTIL_C
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

//general error handling
void print_error_n(char const *const msg)
{
    printf("%s\n", msg);
    exit(1);
}

// h_errno based error handling
void print_error_h(char const *const msg)
{
    printf("%s: %s\n", msg, hstrerror(h_errno));
    exit(1);
}

//errno based error handling
void print_error(char const *const msg)
{
    perror(msg);
    exit(1);
}

void *prepare_buff(u_int8_t type, const void *const data_p, size_t data_size, size_t *new_buff_size)
{
    int tmp_size;
    void *buff_p, *buff_data_p = NULL;
    socklen_t buff_size;

    //calculate buffer size
    if ((tmp_size = inet6_opt_init(NULL, 0)) == -1)
        print_error("ERROR - inet6_opt_init(NULL, 0)");

    if ((tmp_size = inet6_opt_append(NULL, 0, tmp_size, type, (socklen_t)data_size, 8, NULL)) == -1)
        print_error("ERROR - inet6_opt_append(NULL, 0, tmp_size, type, (socklen_t)data_size, 8, NULL) ");

    if ((tmp_size = inet6_opt_finish(NULL, 0, tmp_size)) == -1)
        print_error("ERROR - inet6_opt_finish(NULL, 0, size)");

    buff_size = tmp_size;

    //allocate buffer
    if (!(buff_p = malloc(buff_size)))
        print_error_n("ERROR - malloc(buff_size)");

    memset(buff_p, 0, buff_size);

    //init the buffer
    if ((tmp_size = inet6_opt_init(buff_p, buff_size)) == -1)
        print_error("ERROR - inet6_opt_init(buff_p, buff_size)");

    if ((tmp_size = inet6_opt_append(buff_p, buff_size, tmp_size, type, data_size, 8, &buff_data_p)) == -1)
        print_error("ERROR - inet6_opt_append(buff_p, buff_size, tmp_size, type, data_size, 8, &buff_data_p)");

    //add data into buffer
    if (!buff_data_p)
        print_error_n("ERROR - buff_data_p == NULL after inet6_opt_append(buff_p, buff_size, tmp_size, type, data_size, 8, &buff_data_p)");

    if (data_size != inet6_opt_set_val(buff_data_p, 0, data_p, data_size))
        print_error_n("ERROR - data_size != inet6_opt_set_val(buff_data_p, 0, data_p, data_size)");

    if ((tmp_size = inet6_opt_finish(buff_p, buff_size, tmp_size)) == -1)
        print_error("ERROR - inet6_opt_finish(buff_p, buff_size, tmp_size)");

    if (tmp_size != buff_size)
        print_error_n("EROR - tmp_size != buff_size");

    *new_buff_size = buff_size;
    return buff_p;
}

void print_hex_data(const unsigned char *const buf, const int len)
{
    int i;
    for (i = 0; i < len; i++)
        printf("%02x ", buf[i]);
}

void find_option_data(dst_opt_tlv_t *opt, void *buff_p, uint8_t type)
{
    union
    {
        void *init;
        struct cmsghdr *cmsghdr_p;
        struct ip6_opt *ip6_opt_p;
        struct tlv
        {
            uint8_t type;
            uint8_t len;
            unsigned char data[0];
        } * tlv_p;
        dst_opt_tlv_t *recv_opt_p;
    } data_u;
    if (!buff_p || !opt)
        print_error_n("ERROR - find_option_data: !buff_p || !opt");

    data_u.init = buff_p;
    /* printf("cmsghdr->cmsg_len %d cmsghdr->cmsg_level %d cmsghdr->cmsg_type %d\n",
    (unsigned int)data_u.cmsghdr_p->cmsg_len, data_u.cmsghdr_p->cmsg_level, data_u.cmsghdr_p->cmsg_type);
    */

    data_u.cmsghdr_p++;

    /* printf("ip6_opt->ip6o_type %d ip6_opt->ip6o_len %d\n",
    data_u.ip6_opt_p->ip6o_type, data_u.ip6_opt_p->ip6o_len);
    */

    data_u.ip6_opt_p++;

    printf("Options:\n");
    printf(" tag %d len %d data [", data_u.tlv_p->type, data_u.tlv_p->len);
    print_hex_data((unsigned char *)data_u.tlv_p->data, data_u.tlv_p->len);
    printf("\b]\n");

    data_u.init += data_u.tlv_p->len;
    data_u.tlv_p++;

    printf(" tag 0x%02x len %d data [", (unsigned char)data_u.tlv_p->type, data_u.tlv_p->len);
    print_hex_data((unsigned char *)data_u.tlv_p->data, data_u.tlv_p->len);
    printf("\b]\n");

    data_u.tlv_p++;
    opt->data.port = data_u.recv_opt_p->data.port;
    opt->data.vrf = data_u.recv_opt_p->data.vrf;
    opt->data.flags = data_u.recv_opt_p->data.flags;
    memcpy(opt->data.reserved, data_u.recv_opt_p->data.reserved, sizeof(opt->data.reserved));
    memcpy(opt->data.addr8, data_u.recv_opt_p->data.addr8, sizeof(opt->data.addr8));
    opt->pad.padn = data_u.recv_opt_p->pad.padn;
    opt->pad.len = data_u.recv_opt_p->pad.len;
    memcpy(opt->pad.data, data_u.recv_opt_p->pad.data, sizeof(opt->pad.data));
    return;
}

void print_option_data(const dst_opt_tlv_t *const opt_p)
{
    printf("Option 0x1f:\n");
    printf("  ndst_opt_tlv_t:\n");
    printf("     dst_opt_tlv_data_t:\n");
    printf("        port     0x%02x\n", htons(opt_p->data.port));
    printf("        vrf      0x%02x\n", htons(opt_p->data.vrf));
    printf("        flags    0x%02x\n", htons(opt_p->data.flags));
    printf("        reserved [%02x %02x %02x]\n", opt_p->data.reserved[0], opt_p->data.reserved[1], opt_p->data.reserved[2]);
    printf("        addr8 [");
    print_hex_data((unsigned char *)opt_p->data.addr8, sizeof(opt_p->data.addr8));
    printf("\b]\n");
    printf("     dst_opt_tlv_pad_t:\n");
    printf("        padn  0x%02x\n", opt_p->pad.padn);
    printf("        len   0x%02x\n", opt_p->pad.len);
    printf("        data  [");
    print_hex_data((unsigned char *)opt_p->pad.data, opt_p->pad.len);
    printf("\b]\n");
}