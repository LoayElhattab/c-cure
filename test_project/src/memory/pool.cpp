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
