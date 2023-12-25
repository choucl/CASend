#ifndef _UTIL_H
#define _UTIL_H
#include "packet.h"

void pack_packet_header(packet_header_t *dst, opcode_t opcode, 
                        payload_type_t payload_type, size_t payload_length);

void unpack_packet_header(packet_header_t *src, opcode_t *opcode, 
                        payload_type_t *payload_type, size_t *payload_length);

void pack_packet_payload(packet_payload_t *dst, int num_packet, 
                         size_t cur_payload_size, char *payload);

void unpack_packet_payload(packet_payload_t *src, int *num_packet, 
                           size_t *cur_payload_size, char *payload);

#endif  // _UTIL_H
