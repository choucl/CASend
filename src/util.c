#include "util.h"
#include "packet.h"
#include <string.h>

void pack_packet_header(packet_header_t *dst, opcode_t opcode, 
                        payload_type_t payload_type, size_t payload_length) {
    dst->opcode = opcode;
    dst->payload_type = payload_type;
    dst->payload_length = payload_length;
}

void unpack_packet_header(packet_header_t *src, opcode_t *opcode, 
                        payload_type_t *payload_type, size_t *payload_length) {
    *opcode = src->opcode;
    *payload_type = src->payload_type;
    *payload_length = src->payload_length;
}

void pack_packet_payload(packet_payload_t *dst, int num_packet, 
                         size_t cur_payload_size, char *payload) {
    dst->num_packet = num_packet;
    dst->cur_payload_size = cur_payload_size;
    strncpy(dst->payload, payload, cur_payload_size);
}

void unpack_packet_payload(packet_payload_t *src, int *num_packet, 
                           size_t *cur_payload_size, char *payload) {
    *num_packet = src->num_packet;
    *cur_payload_size = src->cur_payload_size;
    strncpy(payload, src->payload, src->cur_payload_size);
}
