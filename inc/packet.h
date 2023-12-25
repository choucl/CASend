#ifndef _PACKET_H
#define _PACKET_H
#include <stddef.h>

typedef enum opcode {
    kOpAck,
    kOpError,
    kOpCreate,
    kOpRequest,
    kOpPub,
    kOpData,
    kOpFin
} opcode_t;

typedef enum payload_type {
    kNone,
    kCode,
    kPubKey,
    kData,
    kHash
} payload_type_t;

struct packet_header {
    enum opcode opcode;
    enum payload_type payload_type;
    size_t payload_length; // total length, in bytes
};

struct packet_payload {
    int num_packet;
    size_t cur_payload_size;
    char payload[1024];
};

typedef struct packet_header packet_header_t;
typedef struct packet_payload packet_payload_t;

#endif  // _PACKET_H
