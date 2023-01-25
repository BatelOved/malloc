#include <unistd.h>
#include <cstring>

#define SBRK_FAILED ((void*) -1)
#define MAX_BLOCK_SIZE 1e8

struct MallocMetadata {
    size_t size;
    bool is_free;
    MallocMetadata* next;
    MallocMetadata* prev;

    MallocMetadata(size_t size, bool is_free);
    void init(size_t size);
};

MallocMetadata::MallocMetadata(size_t size, bool is_free): size(size), is_free(is_free), next(NULL), prev(NULL) {}

void MallocMetadata::init(size_t size) {
    this->size = size;
    this->is_free = false;
    this->next = NULL;
    this->prev = NULL;
}

struct MemBlockList {
    MallocMetadata* head;
    MallocMetadata* tail;

    MemBlockList();
    void insert(MallocMetadata* p, size_t size);
    void free(void* p);
    MallocMetadata* findFreeSizedBlock(size_t size);
};

MemBlockList::MemBlockList(): head(NULL), tail(NULL) {}

void MemBlockList::insert(MallocMetadata* p, size_t size) {
    p->init(size);
    if (!head) {
        head = p;
        tail = head;
        return;
    }
    tail->next = p;
    p->prev = tail;
    tail = p;
}

void MemBlockList::free(void* p) {
    if (!p) {
        return;
    }
    MallocMetadata* p_meta_data = ((MallocMetadata*)p)-1;
    p_meta_data->is_free = true;
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

    MallocMetadata* reused_block = mem_list.findFreeSizedBlock(size);
    if (reused_block) {
        reused_block->is_free = false;
        return (void*)(reused_block+1);
    }

    MallocMetadata* new_block = (MallocMetadata*)sbrk(size+_size_meta_data());
    if (new_block == SBRK_FAILED) {
        return NULL;
    }
    mem_list.insert(new_block, size);

    return (void*)(new_block+1);
}

void* scalloc(size_t num, size_t size) {
    if (num*size == 0 || num*size > MAX_BLOCK_SIZE) {
        return NULL;
    }
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
    mem_list.free(p);
}

void* srealloc(void* oldp, size_t size) {
    if (size == 0 || size > MAX_BLOCK_SIZE) {
        return NULL;
    }

    if (!oldp) {
        void* new_block = smalloc(size);
        return new_block;
    }
    MallocMetadata* oldp_meta_data = oldp ? (MallocMetadata*)(((MallocMetadata*)oldp)-1) : NULL;

    if (oldp_meta_data && oldp_meta_data->size >= size) {
        return oldp;
    }

    void* new_block = smalloc(size);
    if (!new_block) {
        return NULL;
    }
    std::memmove(new_block, oldp, oldp_meta_data->size);
    sfree(oldp);
    return new_block;
}
