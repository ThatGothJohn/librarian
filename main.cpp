//
// Created by John on 15/12/2021.
//
#include <cstdio>

#include "inject.h"
//TODO(John): allow the dll and procID to be passed in via args

///this will inject a dll using kernel32.dll, hopefully
int main(int argc, char** argv){
    int PID;
    printf_s("Please enter the PID: ");
    scanf_s("%d", &PID);
    printf_s("\n");
    const char* dll_to_inject = "C://temp/demo.dll";

    injectDLL(dll_to_inject,PID);
}

