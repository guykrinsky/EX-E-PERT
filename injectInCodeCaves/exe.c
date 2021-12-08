#include <Windows.h>
#include "exe.h"

#define ERROR -1
#define SUCCESS 0

DWORD set_exe_headers(EXE_file* exe_file)
{
    PIMAGE_SECTION_HEADER first_section_header = { 0 };
    exe_file->dosHeader = exe_file->mapped_handle;
    DWORD relocation_table_end = 0;

    if (exe_file->dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("error in getting the right dos header\n");
        return ERROR;
    }
    exe_file->headers = exe_file->mapped_handle + exe_file->dosHeader->e_lfanew;


    if (exe_file->headers->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("error in getting the right NT header\n");
    }

    if (exe_file->headers->OptionalHeader.Magic != 0x10B)
    {
        printf("this program is not 32 bit \n");
        return ERROR;
    }
    exe_file->entery_address = (DWORD)exe_file->headers->OptionalHeader.ImageBase + exe_file->headers->OptionalHeader.AddressOfEntryPoint;
    first_section_header = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(exe_file->headers);
    exe_file->last_section = (PIMAGE_SECTION_HEADER)(first_section_header + exe_file->headers->FileHeader.NumberOfSections - 1);


    return SUCCESS;
}