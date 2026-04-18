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
