//
// Created by John on 15/12/2021.
//
#include "inject.h"
int injectDLL(const char* dll_path, int PID){

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
    LPVOID mem_alloc = VirtualAllocEx(proc, nullptr, strlen(dll_path), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
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


    getchar();
    return 0;
}
