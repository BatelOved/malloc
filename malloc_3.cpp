#include <unistd.h>
#include <cstring>
#include <sys/mman.h>
#include <stdint.h>
#include <math.h>

#define SBRK_FAILED ((void*) -1)
#define MAX_BLOCK_SIZE 1e8
#define LARGE_BLOCK 128
#define MMAP_LARGE_BLOCK LARGE_BLOCK*1024

int32_t global_cookies = rand();

struct MallocMetadata {
    int32_t cookies;
    size_t size;
    bool is_free;
    MallocMetadata* next;
    MallocMetadata* prev;

    MallocMetadata(size_t size, bool is_free);
    void init(size_t size);
    void verify_block();
};

MallocMetadata::MallocMetadata(size_t size, bool is_free): cookies(0), size(size), is_free(is_free), next(NULL), prev(NULL) {}

void MallocMetadata::init(size_t size) {
    cookies = global_cookies;
    this->size = size;
    this->is_free = false;
    this->next = NULL;
    this->prev = NULL;
}

void MallocMetadata::verify_block() {
    if (cookies != global_cookies) {
        exit(0xdeadbeef);
    }
}

MallocMetadata* wilderness_block = NULL;

struct MemBlockList {
    MallocMetadata* head;
    MallocMetadata* tail;

    MemBlockList();
    void insert(MallocMetadata* p, size_t size);
    void remove(MallocMetadata* p);
    void free(void* p);
    MallocMetadata* findFreeSizedBlock(size_t size);
    bool blockExists(MallocMetadata* p);
    MallocMetadata* findPrevAdjacentBlock(MallocMetadata* p);
    MallocMetadata* findNextAdjacentBlock(MallocMetadata* p);
    void verify_list();
};

MemBlockList::MemBlockList(): head(NULL), tail(NULL) {}

void MemBlockList::insert(MallocMetadata* p, size_t size) {
    // Challenge 0
    p->init(size);
    if (!head) {
        head = p;
        tail = head;
        return;
    }

    if (head && (head->size > size || (head->size == size && p < head))) {
        p->next = head;
        head->prev = p;
        head = p;
        return;
    }

    MallocMetadata* it = head;

    while (it && it->next) {
        if (it->size <= size && (it->next->size > size || (it->next->size == size && p < it->next))) {
            p->prev = it;
            p->next = it->next;
            it->next->prev = p;
            it->next = p;
            return;
        }
        it = it->next;
    }

    tail->next = p;
    p->prev = tail;
    tail = p;
}

void MemBlockList::remove(MallocMetadata* p) {
    MallocMetadata* it = head;
    while (it) {
        if (it == p) {
            it->next && (it->next->prev = it->prev);
            it->prev && (it->prev->next = it->next);
            head == p && (head = p->next);
            tail == p && (tail = p->prev);
            return;
        }
        it = it->next;
    }
}

void MemBlockList::free(void* p) {
    if (!p) {
        return;
    }
    MallocMetadata* p_meta_data = ((MallocMetadata*)p)-1;
    p_meta_data->is_free = true;

    if (p_meta_data->size >= MMAP_LARGE_BLOCK) {
        remove(p_meta_data);
        munmap((void*)(p_meta_data+1), p_meta_data->size);
        return;
    }

    // Challenge 2
    MallocMetadata* prev_adjacent_meta_data = findPrevAdjacentBlock(p_meta_data);
    MallocMetadata* next_adjacent_meta_data = findNextAdjacentBlock(p_meta_data);

    MallocMetadata* prev_free_meta_data = (prev_adjacent_meta_data && prev_adjacent_meta_data->is_free) ? prev_adjacent_meta_data : NULL;
    MallocMetadata* next_free_meta_data = (next_adjacent_meta_data && next_adjacent_meta_data->is_free) ? next_adjacent_meta_data : NULL;

    if (!prev_free_meta_data && !next_free_meta_data) {
        return;
    }

    if (prev_free_meta_data && next_free_meta_data) {
        remove(prev_free_meta_data);
        remove(p_meta_data);
        remove(next_free_meta_data);
        insert(prev_free_meta_data, prev_free_meta_data->size + p_meta_data->size + next_free_meta_data->size + 2*sizeof(MallocMetadata));
        prev_free_meta_data->is_free = true;
        wilderness_block = wilderness_block == next_free_meta_data ? prev_free_meta_data : wilderness_block;
        return;
    }

    prev_free_meta_data = prev_free_meta_data ? prev_free_meta_data : p_meta_data;
    next_free_meta_data = next_free_meta_data ? next_free_meta_data : p_meta_data;

    remove(prev_free_meta_data);
    remove(next_free_meta_data);
    insert(prev_free_meta_data, prev_free_meta_data->size + next_free_meta_data->size + sizeof(MallocMetadata));
    prev_free_meta_data->is_free = true;
    wilderness_block = wilderness_block == next_free_meta_data ? prev_free_meta_data : wilderness_block;
}

MallocMetadata* MemBlockList::findFreeSizedBlock(size_t size) {
    MallocMetadata* it = head;
    while (it) {
        if (it->is_free && it->size >= size) {
            return it;
        }
        it = it->next;
    }
    return NULL;
}

bool MemBlockList::blockExists(MallocMetadata* p) {
    MallocMetadata* it = head;
    while (it) {
        if (it == p) {
            return true;
        }
        it = it->next;
    }
    return false;
}

MallocMetadata* MemBlockList::findPrevAdjacentBlock(MallocMetadata* p) {
    MallocMetadata* it = head;
    MallocMetadata* prev_block = NULL;
    while (it) {
        if (it < p && it > prev_block) {
            prev_block = it;
        }
        it = it->next;
    }
    return prev_block;
}

MallocMetadata* MemBlockList::findNextAdjacentBlock(MallocMetadata* p) {
    MallocMetadata* next_block = (MallocMetadata*)(((size_t)(p+1))+p->size);
    return blockExists(next_block) ? next_block : NULL;
}

void MemBlockList::verify_list() {
    MallocMetadata* it = head;
    while (it) {
        it->verify_block();
        it = it->next;
    }
}

MemBlockList mem_list;

/*********************************Aux methods************************************/

size_t _num_free_blocks() {
    size_t cnt = 0;
    MallocMetadata* it = mem_list.head;
    while (it) {
        if (it->is_free) {
            ++cnt;
        }
        it = it->next;
    }
    return cnt;
}

size_t _num_free_bytes() {
    size_t cnt = 0;
    MallocMetadata* it = mem_list.head;
    while (it) {
        if (it->is_free) {
            cnt += it->size;
        }
        it = it->next;
    }
    return cnt;
}

size_t _num_allocated_blocks() {
    size_t cnt = 0;
    MallocMetadata* it = mem_list.head;
    while (it) {
        ++cnt;
        it = it->next;
    }
    return cnt;
}

size_t _num_allocated_bytes() {
    size_t cnt = 0;
    MallocMetadata* it = mem_list.head;
    while (it) {
        cnt += it->size;
        it = it->next;
    }
    return cnt;
}

size_t _size_meta_data() {
    return sizeof(MallocMetadata);
}

size_t _num_meta_data_bytes() {
    return _num_allocated_blocks()*_size_meta_data();
}

/*********************************API methods************************************/

void* smalloc(size_t size) {
    if (size == 0 || size > MAX_BLOCK_SIZE) {
        return NULL;
    }
    mem_list.verify_list();

    // Challenge 4
    if (size >= MMAP_LARGE_BLOCK) {
        MallocMetadata* new_block = (MallocMetadata*)mmap(NULL, size + _size_meta_data(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (new_block == MAP_FAILED) {
            return NULL;
        }
        mem_list.insert(new_block, size);
        return (void*)(new_block+1);
    }

    MallocMetadata* reused_block = mem_list.findFreeSizedBlock(size);
    if (reused_block) {
        // Challenge 1
        if (reused_block->size >= size + LARGE_BLOCK + _size_meta_data()) {
            MallocMetadata* splitted_block = (MallocMetadata*)((size_t)(reused_block+1) + size);
            splitted_block->size = reused_block->size - size - _size_meta_data();
            mem_list.remove(reused_block);
            mem_list.insert(reused_block, size);
            mem_list.insert(splitted_block, splitted_block->size);
            mem_list.free((void*)(splitted_block+1));
            wilderness_block = wilderness_block == reused_block ? splitted_block : wilderness_block;
            return (void*)(reused_block+1);
        }
        reused_block->is_free = false;
        return (void*)(reused_block+1);
    }

    // Challenge 3
    if (wilderness_block && wilderness_block->is_free) {
        void* new_block = sbrk(size - wilderness_block->size);
        if (new_block == SBRK_FAILED) {
            return NULL;
        }
        wilderness_block->size = size;
        wilderness_block->is_free = false;
        return (void*)(wilderness_block+1);
    }

    MallocMetadata* new_block = (MallocMetadata*)sbrk(size+_size_meta_data());
    if (new_block == SBRK_FAILED) {
        return NULL;
    }
    wilderness_block = new_block;
    mem_list.insert(new_block, size);

    return (void*)(new_block+1);
}

void* scalloc(size_t num, size_t size) {
    if (num*size == 0 || num*size > MAX_BLOCK_SIZE) {
        return NULL;
    }

    mem_list.verify_list();

    void* new_block = smalloc(num*size);
    if (!new_block) {
        return NULL;
    }
    std::memset(new_block, 0, num*size);
    return new_block;
}

void sfree(void* p) {
    if (!p) {
        return;
    }
    mem_list.verify_list();
    mem_list.free(p);
}

void* srealloc(void* oldp, size_t size) {
    if (size == 0 || size > MAX_BLOCK_SIZE) {
        return NULL;
    }

    mem_list.verify_list();

    if (!oldp) {
        void* new_block = smalloc(size);
        return new_block;
    }

    MallocMetadata* oldp_meta_data = (MallocMetadata*)(((MallocMetadata*)oldp)-1);

    if (size >= MMAP_LARGE_BLOCK) {
        if (size <= oldp_meta_data->size) {
            return oldp;
        }
        MallocMetadata* new_block = (MallocMetadata*)mmap(NULL, size + _size_meta_data(), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (new_block == MAP_FAILED) {
            return NULL;
        }

        std::memmove((void*)(new_block+1), oldp, oldp_meta_data->size);
        sfree(oldp);
        
        mem_list.insert(new_block, size);
        return (void*)(new_block+1);
    }

    MallocMetadata* prev_free_adjacent_block = mem_list.findPrevAdjacentBlock(oldp_meta_data);
    MallocMetadata* next_free_adjacent_block = mem_list.findNextAdjacentBlock(oldp_meta_data);
    prev_free_adjacent_block = prev_free_adjacent_block && prev_free_adjacent_block->is_free ? prev_free_adjacent_block : NULL;
    next_free_adjacent_block = next_free_adjacent_block && next_free_adjacent_block->is_free ? next_free_adjacent_block : NULL;
    size_t prev_merged_size = prev_free_adjacent_block ? prev_free_adjacent_block->size + oldp_meta_data->size + _size_meta_data() : 0;
    size_t next_merged_size = next_free_adjacent_block ? next_free_adjacent_block->size + oldp_meta_data->size + _size_meta_data() : 0;

    // case a
    if (oldp_meta_data->size >= size) {
        if (oldp_meta_data->size >= size + LARGE_BLOCK + _size_meta_data()) {
            MallocMetadata* splitted_block = (MallocMetadata*)((size_t)(oldp_meta_data+1) + size);
            splitted_block->size = oldp_meta_data->size - size - _size_meta_data();
            mem_list.remove(oldp_meta_data);
            mem_list.insert(oldp_meta_data, size);
            mem_list.insert(splitted_block, splitted_block->size);
            splitted_block->is_free = true;
            wilderness_block = wilderness_block == oldp_meta_data ? splitted_block : wilderness_block;
            return oldp;
        }
        return oldp;
    }

    // case b
    else if (prev_free_adjacent_block) {
        mem_list.remove(prev_free_adjacent_block);
        mem_list.remove(oldp_meta_data);
        mem_list.insert(prev_free_adjacent_block, prev_merged_size);
        std::memmove((void*)(prev_free_adjacent_block+1), oldp, oldp_meta_data->size);
        wilderness_block = wilderness_block == oldp_meta_data ? prev_free_adjacent_block : wilderness_block;
        return srealloc((void*)(prev_free_adjacent_block+1), size);
    }

    // case c
    else if (wilderness_block == oldp_meta_data) {
        void* new_block = sbrk(size - wilderness_block->size);
        if (new_block == SBRK_FAILED) {
            return NULL;
        }
        wilderness_block->size = size;
        wilderness_block->is_free = false;
        return (void*)(wilderness_block+1);
    }

    // case d
    else if (next_free_adjacent_block) {
        mem_list.remove(next_free_adjacent_block);
        mem_list.remove(oldp_meta_data);
        mem_list.insert(oldp_meta_data, next_merged_size);
        std::memmove((void*)(oldp_meta_data+1), oldp, oldp_meta_data->size);
        wilderness_block = wilderness_block == next_free_adjacent_block ? oldp_meta_data : wilderness_block;
        return srealloc((void*)(oldp_meta_data+1), size);
    }

    // other cases
    void* new_block = smalloc(size);
    if (!new_block) {
        return NULL;
    }
    std::memmove(new_block, oldp, oldp_meta_data->size);
    sfree(oldp);
    return new_block;
}
