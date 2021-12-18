//
// Created by John on 15/12/2021.
//
#include "librarian.h"
int librarian::injectDLL(const char* dll_path, int PID){
    //TODO(John): Allow specifying the dll and function to find and inject with
    //get the process handle
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, false, PID); //
    if (!proc) {
        printf_s("ERROR: No process with the ID:%i could be found", PID);
        return -1;
    }

    //get the address of the LoadLibraryA function in kernel42.dll
    auto LoadLibraryA_addr = (LPVOID) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (!LoadLibraryA_addr) {
        printf_s("ERROR: Could not find LoadLibraryA in kernel32.dll");
        return -1;
    }

    //allocate a new memory region inside the process's address space
    LPVOID mem_alloc = VirtualAllocEx(proc, nullptr, strlen(dll_path)+1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mem_alloc) {
        printf_s("ERROR: Memory could not be allocated inside the given process");
        return -1;
    }

    //write the name of our injected dll into LoadLibraryA
    SIZE_T num_bytes_written = 0;
    bool wrote_bytes = WriteProcessMemory(proc, mem_alloc, dll_path, strlen(dll_path), &num_bytes_written);
    if (!wrote_bytes) {
        printf_s("ERROR: No bytes were written into the process's address space");
        return -1;
    }
    printf_s("Successfully wrote %I64i Bytes\n", num_bytes_written);

    //inject the dll into the process's address space
    HANDLE thread_ID = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA_addr, mem_alloc,
                                          NULL, nullptr);
    if (!thread_ID) {
        printf_s("ERROR: Remote thread could not be created");
        return -1;
    }
    printf_s("Remote Thread created!\nDLL successfully injected.");
    CloseHandle(proc);

    return 0;
}

bool librarian::hook32(void* hook_addr, void* function_to_inject) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    const DWORD PAGE_SIZE = sys_info.dwPageSize;

    BOOL success = true;
    errno_t num_of_errors = 0;
    DWORD old_protection;
    success &= VirtualProtect(hook_addr, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &old_protection); //allow writing to the hook_addr's page
    uint8_t jump_ins [5] = {0xE9, 0x0, 0x0, 0x0, 0x0};
    const auto relative_addr = (uint32_t)((uint64_t)function_to_inject - ((uint64_t)hook_addr + 5)); //compute the relative jump
    num_of_errors += memcpy_s(jump_ins+1, 4, &relative_addr, 4);
    num_of_errors += memcpy_s(hook_addr, 5, jump_ins, 5);    //write the jmp to the hook_addr
    success &= VirtualProtect(hook_addr, PAGE_SIZE, old_protection, nullptr); //reinstate the previous write protection
    return success && num_of_errors == 0;   //fixme(John): we should really exit this function upon reaching an error
}

///allocates the closest free page within a 32-bit distance to the target, or returns nullptr
void* librarian::allocate_close_page(void* target){
    //TODO(John): refactor this function
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    const DWORD PAGE_SIZE = sys_info.dwPageSize;    //get the page size

    uint64_t start_addr = (uint64_t)(target) & ~((uint64_t)PAGE_SIZE - 1); //the address of the page boundary that is before the target
    uint64_t lowest_addr = min(start_addr - 0x7FFFFF00, (uint64_t)sys_info.lpMinimumApplicationAddress);
    uint64_t highest_addr = max(start_addr + 0x7FFFFF00, (uint64_t)sys_info.lpMaximumApplicationAddress);

    uint64_t start_page = (start_addr - (start_addr % PAGE_SIZE)); //the address of the start of the page the target is in

    uint64_t page_offset = 1;
    bool failed = false;
    while (!failed)
    {
        uint64_t byte_offset = page_offset * PAGE_SIZE;
        uint64_t high_addr = start_page + byte_offset;
        uint64_t low_addr = (start_page > byte_offset) ? start_page - byte_offset : 0;

        failed = high_addr > highest_addr && low_addr < lowest_addr;

        if (high_addr < highest_addr)
        {
            void* return_addr = VirtualAlloc((void*)high_addr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (return_addr != nullptr)
                return return_addr;
        }

        if (low_addr > lowest_addr)
        {
            void* return_addr = VirtualAlloc((void*)low_addr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (return_addr != nullptr)
                return return_addr;
        }

        page_offset++;
    }

    return nullptr;
}

bool librarian::hook64(void* hook_addr, void* function_to_inject) {
    //TODO(John): test this function, I think I fucked up somewhere
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    const DWORD PAGE_SIZE = sys_info.dwPageSize;    //get the page size

    void* relay_addr = librarian::allocate_close_page(hook_addr);
    if (relay_addr == nullptr)
        return false;
    uint8_t jump_absolute [] = {0x49, 0xBA, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //mov r10, 0x0 (will be replaced with the injected function addr)
                                0x41, 0xFF, 0xE2  //jmp r10
    };
    memcpy_s(&jump_absolute[2], 8, &function_to_inject, 8);
    memcpy_s(relay_addr, PAGE_SIZE, jump_absolute, sizeof(jump_absolute));

    if (!hook32(hook_addr, (void*)((uint64_t)relay_addr+(13*8)))){
        return false;
    }

    return true;
}

uint64_t librarian::get_base_addr_for_current_process() {
    HANDLE current_proc = GetCurrentProcess();
    HMODULE proc_modules[1024];

    DWORD num_bytes_written = 0;
    EnumProcessModules(current_proc, proc_modules, sizeof(HMODULE) * 1024, &num_bytes_written);

    DWORD num_remote_modules = num_bytes_written / sizeof(HMODULE);
    char proc_name[256];
    GetModuleFileNameEx(current_proc, nullptr, proc_name, 256);
    _strlwr_s(proc_name, 256);

    HMODULE module = 0;

    for (DWORD i = 0; i < num_remote_modules; i++){
        char module_name[256];
        char absolute_module_name[256];
        GetModuleFileNameEx(current_proc, proc_modules[i], module_name, 256);

        _fullpath(absolute_module_name, module_name, 256);
        _strlwr_s(absolute_module_name, 256);

        if (strcmp(proc_name, absolute_module_name) == 0){
            return (uint64_t)proc_modules[i];
        }
    }
    return 0;
}

int librarian::trampoline(void* hook_addr, void* function_to_inject){
    //Unimplemented
    return -1;
}