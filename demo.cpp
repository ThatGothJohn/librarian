//
// Created by John on 15/12/2021.
//

//demo Dll
#include <cstdio>
#include <windows.h>

BOOL WINAPI DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved){
    FILE *file;
    fopen_s(&file, "injected_log.txt", "a+");

    switch (Reason) {
        case DLL_PROCESS_ATTACH:
            fprintf_s(file, "DLL_PROCESS_ATTACH function called\n");
            break;
        case DLL_PROCESS_DETACH:
            fprintf_s(file, "DLL_PROCESS_DETACH function called\n");
            break;
        case DLL_THREAD_ATTACH:
            fprintf_s(file, "DLL_THREAD_ATTACH function called\n");
            break;
        case DLL_THREAD_DETACH:
            fprintf_s(file, "DLL_THREAD_DET"
                            "ACH function called\n");
            break;
        DEFAULT_UNREACHABLE;
    }

    fclose(file);
    return true;
}