#pragma once
#include <cstdint>
#include <cstddef>

#define MAX_PAYLOAD 1024
#define HEADER_SIZE 8

struct PacketHeader {
    uint16_t version;
    uint16_t type;
    uint32_t length;
};

struct Packet {
    PacketHeader header;
    uint8_t*     payload;
};

// Parse raw bytes into a packet structure
Packet* parse_packet(const uint8_t* raw, size_t raw_len);

// Serialize packet to output buffer
int serialize_packet(const Packet* pkt, uint8_t* out, size_t out_len);

// Compute checksum over payload
uint16_t compute_checksum(const uint8_t* data, uint16_t len);

// Free packet resources
void free_packet(Packet* pkt);
