//
// Created by John on 15/12/2021.
//

//demo Dll
#include <cstdio>
#include <windows.h>

INT APIENTRY Demo(HMODULE hDLL, DWORD Reason, LPVOID Reserved){
    FILE *file;
    fopen_s(&file, "C://temp.txt", "a+");

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
    }

    fclose(file);
    return 0;
}