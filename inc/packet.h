#ifndef _PACKET_H
#define _PACKET_H
#include <stddef.h>

#define HEADER_LENGTH  (3 * sizeof(int))
#define GET_PAYLOAD_PACKET_LEN(payload_length) \
            ((payload_length) + 2 * sizeof(int))

typedef enum opcode {
    kOpAck = 0,
    kOpError,
    kOpCreate,
    kOpRequest,
    kOpPub,
    kOpData,
    kOpFin
} opcode_t;

typedef enum payload_type {
    kNone = 0,
    kCode,
    kPubKey,
    kData,
    kHash
} payload_type_t;

typedef char * packet_header_t;
typedef char * packet_payload_t;

// input: packet_header - unallocated packet_header_t pointer
// return value:
//   -1: error
//   0 : correct
int create_header(packet_header_t *packet_header, opcode_t opcode,
                  payload_type_t payload_type, size_t payload_length);

// input: packet_payload - unallocated packet_payload_t pointer
// return value:
//   -1    : error
//   others: length of whole packet
int create_payload(packet_payload_t *packet_payload, int num_packet,
                   size_t cur_payload_size, char *payload);

// helper functions to retrieve information
opcode_t get_opcode(packet_header_t header);
payload_type_t get_payload_type(packet_header_t header);
size_t get_payload_length(packet_header_t header);
int get_packet_num(packet_payload_t payload);
size_t get_cur_payload_size(packet_payload_t payload);

// input: dst - unallocated char * pointer
// return value:
//   -1: error
//   0 : correct
int copy_payload(packet_payload_t payload, char **dst);

// check header opcode match or not
// return value:
//   -1: mismatch
//   0: match
int check_header_op(packet_header_t header, opcode_t expected_opcode);

#endif  // _PACKET_H
