//
// Created by John on 15/12/2021.
//

#ifndef LIBRARIAN_H
#define LIBRARIAN_H
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <Psapi.h>

namespace librarian {

    int injectDLL(const char*, int);

    bool hook32(void*, void*);

    bool hook64(void*,void*);

    int trampoline(void*, void*);

    void* allocate_close_page(void*);

    uint64_t get_base_addr_for_current_process();

}
#endif //LIBRARIAN_H
