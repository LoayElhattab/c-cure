#include "packet.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>

struct Session {
    int      socket_fd;
    uint8_t* recv_buf;
    size_t   buf_size;
    uint32_t seq;
};

// Allocate a session with a receive buffer sized to capacity
// BUG (CWE-190): num_slots * slot_size can overflow uint32_t, producing tiny buffer
Session* create_session(int fd, uint32_t num_slots, uint32_t slot_size) {
    Session* s = (Session*)malloc(sizeof(Session));
    s->socket_fd = fd;
    s->buf_size  = num_slots * slot_size;   // integer overflow — no overflow check
    s->recv_buf  = (uint8_t*)malloc(s->buf_size);
    s->seq       = 0;
    return s;
}

// Receive and process a packet from the session
// BUG (CWE-415): if parse_packet fails and returns null, we still call free_packet(pkt)
// later free_packet is called again by the caller on the same pointer
int receive_packet(Session* s, size_t incoming_len) {
    Packet* pkt = parse_packet(s->recv_buf, incoming_len);

    if (!pkt) {
        free(s->recv_buf);   // frees recv_buf
        free(s->recv_buf);   // BUG (CWE-415): second free of same pointer
        return -1;
    }

    printf("Received packet type %u seq %u
", pkt->header.type, s->seq++);
    free_packet(pkt);
    return 0;
}

// Resize session buffer — replaces recv_buf
// BUG (CWE-476): realloc can return null; if it does, old buf is lost and
// s->recv_buf becomes null — next access dereferences null
void resize_buffer(Session* s, size_t new_size) {
    s->recv_buf = (uint8_t*)realloc(s->recv_buf, new_size);
    s->buf_size = new_size;
    // no null check — if realloc fails, s->recv_buf is now null
}

void destroy_session(Session* s) {
    if (!s) return;
    free(s->recv_buf);
    free(s);
}
