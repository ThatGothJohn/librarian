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
    printf_s("Successfully wrote %i Bytes\n", num_bytes_written);

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

    bool success = true;
    errno_t num_of_errors = 0;
    DWORD old_protection;
    success &= VirtualProtect(hook_addr, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &old_protection); //allow writing to the hook_addr
    uint8_t jump_ins [5] = {0xE9, 0x0, 0x0, 0x0, 0x0};
    const uint32_t relative_addr = (uint32_t)function_to_inject - ((uint32_t)hook_addr + 5); //compute the relative jump
    num_of_errors += memcpy_s(jump_ins+1, 4, &relative_addr, 4);
    num_of_errors += memcpy_s(hook_addr, 5, jump_ins, 5);    //write the jmp to the hook_addr
    success &= VirtualProtect(hook_addr, PAGE_SIZE, old_protection, nullptr); //reinstate the previous write protection
    return success && num_of_errors == 0;   //fixme(John): we should really exit this function upon reaching an error
}

bool librarian::hook64(void* hook_addr, void* funtion_to_inject) {
    //Unimplemented
    return false;
}

int librarian::trampoline(void* hook_addr, void* function_to_inject){
    //Unimplemented
    return -1;
}