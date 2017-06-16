#include <config.h>
#include <openflow/openflow.h>
#include <openflow/nicira-ext.h>

#ifndef NICIRA_CUST
#define NICIRA_CUST

/* Nicira Extension defined messages in order to transmit user-space statistics
 * to connected controllers */
struct netlink_stats_request {
    ovs_be16 flag;
    uint8_t pad[2];           /* Align to 4 byte. */
};
OFP_ASSERT(sizeof(struct netlink_stats_request) == 4);

struct netlink_stats_enable {
    ovs_be16 flag;
    uint8_t pad[2];           /* Align to 4 byte. */
};
OFP_ASSERT(sizeof(struct netlink_stats_enable) == 4);

struct netlink_stats_disable {
    ovs_be16 flag;
    uint8_t pad[2];           /* Align to 4 byte. */
};
OFP_ASSERT(sizeof(struct netlink_stats_disable) == 4);

struct ofp_exp_enable_req {
    struct ofp_header header;
    ovs_be32 vendor;
    ovs_be32 subtype;
    struct netlink_stats_disable data;
};
OFP_ASSERT(sizeof(struct ofp_exp_enable_req) == 20);

struct netlink_stats_ipv4_reply {
    ovs_be32 src_ip;
    ovs_be32 dst_ip;
    ovs_be16 src_port;
    ovs_be16 dst_port;
    uint8_t proto;
    uint8_t pad[3];
};

struct netlink_stats_reply {
    struct netlink_stats_ipv4_reply ipv4;   /* 16 */
    ovs_be32 pkt_count;                     /* 4 */
    ovs_be16 pkt_size_max;                  /* 2 */
    ovs_be16 pkt_size[5000];                /* 10000 */
    uint8_t pad[2];                         /* 2 */
};
OFP_ASSERT(sizeof(struct netlink_stats_reply) == 10024);

/* Nicira Vendor Message OVS 2.5.0 */

struct cn_ofp11_stats_msg {
    struct ofp_header header;
    ovs_be16 type;              /* One of the OFPST_* constants. */
    ovs_be16 flags;             /* OFPSF_REQ_* flags (none yet defined). */
    uint8_t pad[4];
    /* Followed by the body of the request. */
};

/* Vendor extension stats message. */
struct x_25_vendor_stats_msg {
    struct cn_ofp11_stats_msg osm; /* Type OFPST_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
};
//OFP_ASSERT(sizeof(struct x_25_vendor_stats_msg) == 20);

struct x_25_nicira11_stats_msg {
    struct x_25_vendor_stats_msg vsm; /* Vendor NX_VENDOR_ID. */
    ovs_be32 subtype;            /* Vendor-specific subtype. */
};
//OFP_ASSERT(sizeof(struct x_25_nicira11_stats_msg) == 24);

/* Nicira Vendor Message OVS 2.6.0+ */
/* Vendor extension stats message. */
struct x_26_vendor_stats_msg {
    struct cn_ofp11_stats_msg osm; /* Type OFPST_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
    ovs_be32 subtype;           /* Vendor-specific subtype. */
};
//OFP_ASSERT(sizeof(struct ofp11_vendor_stats_msg) == 24);

#endif /* NICIRA_CUST */
