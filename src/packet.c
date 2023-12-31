#include "packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

int create_header(packet_header_t *packet_header, opcode_t opcode,
                  payload_type_t payload_type, size_t payload_length) {
  *packet_header = malloc(3 * sizeof(int));
  if (*packet_header == NULL) return -1;
  ((int *)*packet_header)[0] = opcode;
  ((int *)*packet_header)[1] = payload_type;
  ((int *)*packet_header)[2] = payload_length;
  return 1;
}

int create_payload(packet_payload_t *packet_payload, int num_packet,
                   size_t cur_payload_size, char *payload) {
  int total_size = 2 * sizeof(int) + cur_payload_size;
  *packet_payload = malloc(total_size);
  if (*packet_payload == NULL) return -1;
  ((int *)*packet_payload)[0] = num_packet;
  ((int *)*packet_payload)[1] = cur_payload_size;
  memcpy(&(*packet_payload)[2 * sizeof(int)], payload, cur_payload_size);
  return total_size;
}

opcode_t get_opcode(packet_header_t header) {
  if (header == NULL)
    return -1;
  else
    return *(int *)(header + 0 * sizeof(int));
}
payload_type_t get_payload_type(packet_header_t header) {
  if (header == NULL)
    return -1;
  else
    return *(int *)(header + 1 * sizeof(int));
}
size_t get_payload_length(packet_header_t header) {
  if (header == NULL)
    return -1;
  else
    return *(int *)(header + 2 * sizeof(int));
}
int get_packet_num(packet_payload_t payload) {
  if (payload == NULL)
    return -1;
  else
    return *(int *)(payload + 0 * sizeof(int));
}
size_t get_cur_payload_size(packet_payload_t payload) {
  if (payload == NULL)
    return -1;
  else
    return *(int *)(payload + 1 * sizeof(int));
}
int copy_payload(packet_payload_t payload, char **dst) {
  size_t payload_size = get_cur_payload_size(payload);
  *dst = malloc(sizeof(char) * payload_size);
  if (*dst == NULL) return -1;
  memcpy(*dst, &payload[2 * sizeof(int)], payload_size);
  return 1;
}

int check_header_op(packet_header_t header, opcode_t expected_opcode) {
  int receive_opcode = get_opcode(header);
  if (receive_opcode != expected_opcode) {
    error(0, "header opcode mismatch, expected: , get: ", receive_opcode,
          expected_opcode);
    return -1;
  }
  return 1;
}
