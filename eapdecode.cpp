#include <netinet/in.h>

#define ETHERTYPE_8021Q 0x8100
#define ETHERTYPE_EAPOL 0x888e

// modifies data and data_len to skip ethernet header
// returns ethernet payload type, or 0 on failure
static uint32_t ethernet_unwrap(const uint8_t **ptr_data, uint32_t *ptr_data_len)
{
    struct eth
    {
        uint8_t dest[6];
        uint8_t src[6];
        uint16_t type;
    } __attribute__((packed));

    struct eth_8021q
    {
        uint8_t dest[6];
        uint8_t src[6];
        uint16_t tag_protocol_id;
        uint16_t tag_control_info;
        uint16_t type;
    } __attribute__((packed));

    const uint8_t *data = *ptr_data;
    uint32_t data_len = *ptr_data_len;

    if (data_len <= sizeof(eth))
    {
        return 0;
    }

    struct eth *e = (struct eth *) data;
    if (ntohs(e->type) == ETHERTYPE_8021Q)
    {
        if (data_len <= sizeof(eth_8021q))
        {
            return 0;
        }

        struct eth_8021q *eq = (struct eth_8021q *) data;
        *ptr_data += sizeof(struct eth_8021q);
        *ptr_data_len -= sizeof(struct eth_8021q);
        return ntohs(eq->type);
    } else {
        *ptr_data += sizeof(struct eth);
        *ptr_data_len -= sizeof(struct eth);
        return ntohs(e->type);
    }
}

// check if current packet is an EAP success message
bool is_eapol_success(const uint8_t *data, uint32_t data_len)
{
    uint32_t eth_type = ethernet_unwrap(&data, &data_len);
    if (eth_type != ETHERTYPE_EAPOL)
    {
        return false;
    }

#define EAPOL_PACKET_TYPE_EAP       0x0000
#define EAPOL_PACKET_TYPE_START     0x0001
#define EAPOL_PACKET_TYPE_LOGOFF    0x0002
#define EAPOL_PACKET_TYPE_KEY       0x0003

    struct eapol_hdr
    {
        uint8_t version;
        uint8_t type;
        uint16_t length;
    } __attribute__((packed));

    if (data_len <= sizeof(struct eapol_hdr))
    {
        return false;
    }

    struct eapol_hdr *hdr = (struct eapol_hdr *) data;
    if (hdr->type != EAPOL_PACKET_TYPE_EAP)
    {
        return false;
    }

    if (data_len <= sizeof(struct eapol_hdr))
    {
        return false;
    }

    data += sizeof(eapol_hdr);
    data_len -= sizeof(eapol_hdr);

#define EAP_MSG_TYPE_INVALID    0
#define EAP_MSG_TYPE_REQUEST    1
#define EAP_MSG_TYPE_RESPONSE   2
#define EAP_MSG_TYPE_SUCCESS    3
#define EAP_MSG_TYPE_FAILURE    4
#define EAP_MSG_TYPE_INITIATE   5
#define EAP_MSG_TYPE_FINISH     6

    struct eap_frame
    {
        uint8_t msg_type;
        uint8_t id;
        uint16_t len;
    } __attribute__((packed));

    struct eap_frame *frame = (struct eap_frame *) data;

    if (frame->msg_type == EAP_MSG_TYPE_SUCCESS)
    {
        return true;
    } else {
        return false;
    }
}