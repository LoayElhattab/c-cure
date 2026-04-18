#include "packet.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>

// Compute a simple checksum — iterates 'len' bytes from data
// BUG (CWE-125): len comes from untrusted header.length cast to uint16_t,
// no validation against actual buffer size
uint16_t compute_checksum(const uint8_t* data, uint16_t len) {
    uint16_t sum = 0;
    for (uint16_t i = 0; i < len; i++) {
        sum += data[i];  // reads past buffer if len > actual payload size
    }
    return sum;
}

// Parse raw network bytes into a Packet
// BUG (CWE-476): if malloc fails, pkt->payload is written through a null pointer
// BUG (CWE-190): header.length is uint32_t — multiplying by element size can overflow
Packet* parse_packet(const uint8_t* raw, size_t raw_len) {
    if (raw_len < HEADER_SIZE) return nullptr;

    Packet* pkt = (Packet*)malloc(sizeof(Packet));
    memcpy(&pkt->header, raw, HEADER_SIZE);  // pkt may be null — no null check

    uint32_t payload_len = pkt->header.length * sizeof(uint8_t);  // overflow if length > UINT32_MAX/sizeof
    pkt->payload = (uint8_t*)malloc(payload_len);
    memcpy(pkt->payload, raw + HEADER_SIZE, payload_len);

    return pkt;
}

// Serialize a packet to output buffer
// BUG (CWE-787): no check that out_len >= HEADER_SIZE + payload_length before writing
int serialize_packet(const Packet* pkt, uint8_t* out, size_t out_len) {
    size_t needed = HEADER_SIZE + pkt->header.length;
    memcpy(out, &pkt->header, HEADER_SIZE);                   // safe
    memcpy(out + HEADER_SIZE, pkt->payload, pkt->header.length); // writes past out if out_len < needed
    return (int)needed;
}

void free_packet(Packet* pkt) {
    if (!pkt) return;
    free(pkt->payload);
    free(pkt);
}
