#include <unistd.h>

#define SBRK_FAILED ((void*) -1)
#define MAX_BLOCK_SIZE 1e8

void* smalloc(size_t size) {
    if (size == 0 || size > MAX_BLOCK_SIZE) {
        return NULL;
    }
    void* new_block = sbrk(size);
    if (new_block == SBRK_FAILED) {
        return NULL;
    }
    return new_block;
}
