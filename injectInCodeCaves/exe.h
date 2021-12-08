#pragma once
#include <Windows.h>

struct Exe_file
{
    HANDLE handle;
    LPBYTE mapped_handle;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS headers;
    PIMAGE_SECTION_HEADER last_section;
    DWORD entry_address;
    DWORD file_size;
};

typedef struct Exe_file EXE_file;

DWORD set_exe_headers(EXE_file*);
