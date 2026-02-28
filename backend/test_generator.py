"""
Generates a realistic multi-file C++ project for testing C-Cure.
Files contain subtle, realistic vulnerabilities across all 6 trained CWEs.
Usage: python generate_test_project.py
Output: ./test_project/ folder
"""

import os

FILES = {}

# ─────────────────────────────────────────────
# src/network/packet.h
# ─────────────────────────────────────────────
FILES["src/network/packet.h"] = """\
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
"""

# ─────────────────────────────────────────────
# src/network/packet.cpp
# CWE-125 (oob read in checksum), CWE-787 (oob write in serialize),
# CWE-190 (integer overflow in length calc), CWE-476 (null deref in parse)
# ─────────────────────────────────────────────
FILES["src/network/packet.cpp"] = """\
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
"""

# ─────────────────────────────────────────────
# src/network/session.cpp
# CWE-415 (double free on error path), CWE-476 (null deref),
# CWE-190 (overflow in buffer sizing)
# ─────────────────────────────────────────────
FILES["src/network/session.cpp"] = """\
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

    printf("Received packet type %u seq %u\n", pkt->header.type, s->seq++);
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
"""

# ─────────────────────────────────────────────
# src/crypto/cipher.cpp
# CWE-787 (oob write in key schedule), CWE-125 (oob read in block processing),
# CWE-369 (divide by zero in padding calc)
# ─────────────────────────────────────────────
FILES["src/crypto/cipher.cpp"] = """\
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cstdio>

#define BLOCK_SIZE 16
#define MAX_KEY_LEN 32

struct CipherCtx {
    uint8_t  key[MAX_KEY_LEN];
    uint8_t  subkeys[11][MAX_KEY_LEN];
    int      rounds;
    uint32_t block_count;
};

// Expand key into subkeys for each round
// BUG (CWE-787): rounds comes from caller — if rounds > 11, writes past subkeys array
void expand_key(CipherCtx* ctx, const uint8_t* key, int key_len, int rounds) {
    ctx->rounds = rounds;
    memcpy(ctx->key, key, key_len > MAX_KEY_LEN ? MAX_KEY_LEN : key_len);

    for (int r = 0; r < rounds; r++) {  // if rounds > 11, r indexes out of subkeys[11]
        for (int i = 0; i < MAX_KEY_LEN; i++) {
            ctx->subkeys[r][i] = ctx->key[i] ^ (uint8_t)(r * 0x36 + i);
        }
    }
}

// Encrypt a buffer in-place using the subkeys
// BUG (CWE-125): reads ctx->subkeys[round] where round = block_count % ctx->rounds
// if ctx->rounds is 0 — divide by zero; if block_count overflows — wrong index
uint8_t* encrypt_block(CipherCtx* ctx, uint8_t* block, size_t block_len) {
    // BUG (CWE-369): if ctx->rounds == 0, modulo is undefined
    int round = ctx->block_count % ctx->rounds;
    ctx->block_count++;

    for (size_t i = 0; i < block_len; i++) {
        // BUG (CWE-125): round could be >= 11 if expand_key was called with rounds > 11
        block[i] ^= ctx->subkeys[round][i % MAX_KEY_LEN];
    }
    return block;
}

// Compute required padded length
// BUG (CWE-369): if BLOCK_SIZE is somehow 0, division by zero
size_t padded_length(size_t input_len, size_t block_size) {
    size_t remainder = input_len % block_size;  // UB if block_size == 0
    if (remainder == 0) return input_len;
    return input_len + (block_size - remainder);
}

// Decrypt buffer — allocates output
// CLEAN: proper bounds, null checks, size validation
uint8_t* decrypt_buffer(CipherCtx* ctx, const uint8_t* input, size_t len, size_t* out_len) {
    if (!ctx || !input || len == 0) return nullptr;
    *out_len = len;
    uint8_t* out = (uint8_t*)malloc(len);
    if (!out) return nullptr;
    memcpy(out, input, len);
    return out;
}
"""

# ─────────────────────────────────────────────
# src/storage/filestore.cpp
# CWE-125 (oob read in index), CWE-787 (oob write in write_entry),
# CWE-476 (null deref after failed open), CWE-415 (double free on error)
# ─────────────────────────────────────────────
FILES["src/storage/filestore.cpp"] = """\
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#define MAX_ENTRIES 64
#define ENTRY_SIZE  256

struct Store {
    char   entries[MAX_ENTRIES][ENTRY_SIZE];
    int    count;
    FILE*  log_fp;
};

// Open a store backed by a log file
// BUG (CWE-476): fopen can return null if path is invalid;
// log_fp is used later without null check
Store* open_store(const char* log_path) {
    Store* s = (Store*)calloc(1, sizeof(Store));
    s->log_fp = fopen(log_path, "a+");  // may return null
    return s;
}

// Write entry at position idx
// BUG (CWE-787): idx is not validated against MAX_ENTRIES
// BUG (CWE-125): strlen(data) not validated against ENTRY_SIZE — strncpy truncates
// but the log write uses strlen(data) which may read past data
void write_entry(Store* s, int idx, const char* data) {
    strncpy(s->entries[idx], data, ENTRY_SIZE);  // idx may be >= MAX_ENTRIES
    // BUG (CWE-476): s->log_fp may be null
    fprintf(s->log_fp, "WRITE[%d]: %.*s\n", idx, (int)strlen(data), data);
}

// Read entry at position idx and return a heap copy
// BUG (CWE-125): idx not validated, reads arbitrary memory if idx >= MAX_ENTRIES
char* read_entry(Store* s, int idx) {
    char* out = (char*)malloc(ENTRY_SIZE);
    if (!out) return nullptr;
    memcpy(out, s->entries[idx], ENTRY_SIZE);  // out-of-bounds read if idx >= 64
    return out;
}

// Close and free a store
// BUG (CWE-415): if open_store failed partially and close_store is called twice,
// s->log_fp is closed and then fclose called again on same pointer
void close_store(Store* s) {
    if (!s) return;
    if (s->log_fp) {
        fclose(s->log_fp);
        s->log_fp = nullptr;
    }
    free(s);
}

// Compact store — remove deleted entries
// CLEAN: bounds checked, safe copy
int compact_store(Store* s) {
    if (!s || s->count <= 0) return 0;
    int new_count = 0;
    char temp[MAX_ENTRIES][ENTRY_SIZE];
    for (int i = 0; i < s->count && i < MAX_ENTRIES; i++) {
        if (s->entries[i][0] != '\0') {
            memcpy(temp[new_count++], s->entries[i], ENTRY_SIZE);
        }
    }
    memcpy(s->entries, temp, sizeof(temp));
    s->count = new_count;
    return new_count;
}
"""

# ─────────────────────────────────────────────
# src/parser/config_parser.c
# CWE-190 (overflow in line count), CWE-125 (oob read),
# CWE-369 (div by zero in avg), CWE-787 (oob write in unescape)
# ─────────────────────────────────────────────
FILES["src/parser/config_parser.c"] = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LINE   512
#define MAX_KEYS   128

typedef struct {
    char key[64];
    char value[256];
} ConfigEntry;

typedef struct {
    ConfigEntry entries[MAX_KEYS];
    int         count;
    uint32_t    total_bytes_read;
} Config;

/* Parse a config file line by line
 * BUG (CWE-190): total_bytes_read accumulates line lengths as uint32_t
 * on very large files this overflows, corrupting the count
 * BUG (CWE-125): strtok result used without length validation
 */
Config* parse_config(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return NULL;

    Config* cfg = (Config*)calloc(1, sizeof(Config));
    char line[MAX_LINE];

    while (fgets(line, MAX_LINE, f) && cfg->count < MAX_KEYS) {
        cfg->total_bytes_read += (uint32_t)strlen(line);  /* CWE-190: overflows on large file */

        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';

        strncpy(cfg->entries[cfg->count].key,   line,   63);
        strncpy(cfg->entries[cfg->count].value, eq + 1, 255);
        cfg->count++;
    }

    fclose(f);
    return cfg;
}

/* Compute average value length across all entries
 * BUG (CWE-369): if cfg->count is 0, division by zero
 */
float avg_value_length(const Config* cfg) {
    int total = 0;
    for (int i = 0; i < cfg->count; i++) {
        total += (int)strlen(cfg->entries[i].value);
    }
    return (float)total / cfg->count;  /* CWE-369: division by zero if count == 0 */
}

/* Unescape backslash sequences in-place
 * BUG (CWE-787): dst has same size as src but we don't track dst write position
 * multi-byte escape sequences can write one past the end
 */
void unescape_value(char* src, char* dst, size_t dst_size) {
    size_t i = 0, j = 0;
    while (src[i] && j < dst_size) {
        if (src[i] == '\\' && src[i+1]) {
            dst[j++] = src[i+1];  /* BUG (CWE-787): j < dst_size not checked after increment */
            i += 2;
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';  /* CWE-787: writes one past end if j == dst_size */
}

/* Get value by key — returns pointer into config entries
 * BUG (CWE-125): linear scan reads cfg->entries[i] without checking i < MAX_KEYS
 * if cfg->count was corrupted by overflow, reads past entries array
 */
const char* get_value(const Config* cfg, const char* key) {
    for (int i = 0; i < cfg->count; i++) {  /* cfg->count may exceed MAX_KEYS due to CWE-190 */
        if (strcmp(cfg->entries[i].key, key) == 0)
            return cfg->entries[i].value;
    }
    return NULL;
}

/* Safe helper — clean function
 * Validates all bounds before accessing
 */
int config_entry_count(const Config* cfg) {
    if (!cfg) return 0;
    return cfg->count < MAX_KEYS ? cfg->count : MAX_KEYS;
}
"""

# ─────────────────────────────────────────────
# src/memory/pool.cpp
# CWE-415 (double free), CWE-476 (null deref),
# CWE-190 (overflow in pool sizing), CLEAN functions mixed in
# ─────────────────────────────────────────────
FILES["src/memory/pool.cpp"] = """\
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdio>

struct Block {
    void*   ptr;
    size_t  size;
    bool    in_use;
};

struct MemPool {
    Block*   blocks;
    uint32_t capacity;
    uint32_t used;
};

// Create a pool with given block count and block size
// BUG (CWE-190): capacity * block_size overflows if both are large
MemPool* pool_create(uint32_t capacity, uint32_t block_size) {
    MemPool* pool   = (MemPool*)malloc(sizeof(MemPool));
    pool->capacity  = capacity;
    pool->used      = 0;
    size_t total    = (size_t)capacity * block_size;  // CWE-190: overflow before cast
    pool->blocks    = (Block*)malloc(sizeof(Block) * capacity);

    for (uint32_t i = 0; i < capacity; i++) {
        pool->blocks[i].ptr    = malloc(block_size);
        pool->blocks[i].size   = block_size;
        pool->blocks[i].in_use = false;
    }
    return pool;
}

// Allocate a block from the pool
// CLEAN: validates pool and capacity before use
void* pool_alloc(MemPool* pool) {
    if (!pool || pool->used >= pool->capacity) return nullptr;
    for (uint32_t i = 0; i < pool->capacity; i++) {
        if (!pool->blocks[i].in_use) {
            pool->blocks[i].in_use = true;
            pool->used++;
            return pool->blocks[i].ptr;
        }
    }
    return nullptr;
}

// Free a specific pointer back to the pool
// BUG (CWE-415): no in_use check before marking free —
// calling pool_free twice on the same pointer marks it free twice
// and allows double allocation; if the block is then freed via pool_destroy,
// the underlying ptr is freed twice
void pool_free(MemPool* pool, void* ptr) {
    if (!pool || !ptr) return;
    for (uint32_t i = 0; i < pool->capacity; i++) {
        if (pool->blocks[i].ptr == ptr) {
            pool->blocks[i].in_use = false;  // no check if already false
            pool->used--;
            return;
        }
    }
}

// Resize the pool to a new capacity
// BUG (CWE-476): realloc may return null — if so, pool->blocks becomes null
// and the subsequent loop dereferences it
void pool_resize(MemPool* pool, uint32_t new_capacity) {
    pool->blocks   = (Block*)realloc(pool->blocks, sizeof(Block) * new_capacity);
    // BUG (CWE-476): pool->blocks may now be null
    for (uint32_t i = pool->capacity; i < new_capacity; i++) {
        pool->blocks[i].ptr    = malloc(64);
        pool->blocks[i].in_use = false;
        pool->blocks[i].size   = 64;
    }
    pool->capacity = new_capacity;
}

// Destroy the pool and all blocks
// CLEAN: proper null checks and cleanup
void pool_destroy(MemPool* pool) {
    if (!pool) return;
    if (pool->blocks) {
        for (uint32_t i = 0; i < pool->capacity; i++) {
            if (pool->blocks[i].ptr) {
                free(pool->blocks[i].ptr);
                pool->blocks[i].ptr = nullptr;
            }
        }
        free(pool->blocks);
        pool->blocks = nullptr;
    }
    free(pool);
}
"""

# ─────────────────────────────────────────────
# src/utils/string_ops.cpp
# MOSTLY CLEAN — a few subtle issues mixed in
# CWE-125 (oob read in find), CWE-787 (oob write in join)
# ─────────────────────────────────────────────
FILES["src/utils/string_ops.cpp"] = """\
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cctype>

// CLEAN: safely compute length of a null-terminated string with upper bound
size_t safe_strlen(const char* s, size_t max_len) {
    if (!s) return 0;
    size_t i = 0;
    while (i < max_len && s[i]) i++;
    return i;
}

// CLEAN: safe copy with guaranteed null termination
void safe_strcpy(char* dst, const char* src, size_t dst_size) {
    if (!dst || !src || dst_size == 0) return;
    size_t i = 0;
    while (i < dst_size - 1 && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\\0';
}

// BUG (CWE-125): searches for pattern in text using text_len as bound
// but accesses text[i + j] where j goes up to pattern_len — can read past text+text_len
int find_pattern(const char* text, size_t text_len, const char* pattern, size_t pattern_len) {
    for (size_t i = 0; i <= text_len - pattern_len; i++) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; j++) {
            if (text[i + j] != pattern[j]) {  // CWE-125: i+j may exceed text_len
                match = false;
                break;
            }
        }
        if (match) return (int)i;
    }
    return -1;
}

// BUG (CWE-787): joins strings into a fixed-size buffer of out_size bytes
// does not check total length before writing — can overflow out
void str_join(const char** parts, int count, char sep, char* out, size_t out_size) {
    size_t pos = 0;
    for (int i = 0; i < count; i++) {
        size_t len = strlen(parts[i]);
        memcpy(out + pos, parts[i], len);  // CWE-787: no check that pos+len < out_size
        pos += len;
        if (i < count - 1) out[pos++] = sep;
    }
    out[pos] = '\\0';
}

// CLEAN: trim leading and trailing whitespace in-place
void str_trim(char* s) {
    if (!s || !*s) return;
    // trim leading
    int start = 0;
    while (s[start] && isspace((unsigned char)s[start])) start++;
    memmove(s, s + start, strlen(s) - start + 1);
    // trim trailing
    int end = (int)strlen(s) - 1;
    while (end >= 0 && isspace((unsigned char)s[end])) s[end--] = '\\0';
}

// CLEAN: convert string to integer with error detection
int str_to_int_safe(const char* s, int* out, int default_val) {
    if (!s || !out) return -1;
    char* end;
    long val = strtol(s, &end, 10);
    if (end == s || *end != '\\0') {
        *out = default_val;
        return -1;
    }
    *out = (int)val;
    return 0;
}
"""


def write_project(base_dir: str):
    for rel_path, content in FILES.items():
        full_path = os.path.join(base_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  wrote {rel_path}")


def print_summary():
    total_functions = 0
    vuln_functions  = 0
    cwes_used       = set()

    # rough counts from what we wrote
    manifest = [
        # (file, vuln_fns, clean_fns, cwes)
        ("src/network/packet.cpp",    3, 1, {"CWE-125","CWE-787","CWE-190","CWE-476"}),
        ("src/network/session.cpp",   3, 1, {"CWE-190","CWE-415","CWE-476"}),
        ("src/crypto/cipher.cpp",     3, 1, {"CWE-787","CWE-125","CWE-369"}),
        ("src/storage/filestore.cpp", 4, 1, {"CWE-125","CWE-787","CWE-476","CWE-415"}),
        ("src/parser/config_parser.c",4, 1, {"CWE-190","CWE-125","CWE-369","CWE-787"}),
        ("src/memory/pool.cpp",       3, 2, {"CWE-190","CWE-415","CWE-476"}),
        ("src/utils/string_ops.cpp",  2, 4, {"CWE-125","CWE-787"}),
    ]

    print("\n  Coverage summary:")
    for name, vuln, clean, cwes in manifest:
        total_functions += vuln + clean
        vuln_functions  += vuln
        cwes_used.update(cwes)
        print(f"    {name}: {vuln} vuln, {clean} clean — {', '.join(sorted(cwes))}")

    print(f"\n  Total functions : {total_functions}")
    print(f"  Vulnerable      : {vuln_functions}")
    print(f"  Clean           : {total_functions - vuln_functions}")
    print(f"  CWEs covered    : {', '.join(sorted(cwes_used))}")


if __name__ == "__main__":
    base = "test_project"
    print(f"Generating test project in ./{base}/\n")
    write_project(base)
    print_summary()
    print(f"\n✓ Done. Upload the '{base}' folder to C-Cure.")