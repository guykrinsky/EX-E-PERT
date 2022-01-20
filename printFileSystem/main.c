#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#pragma warning(disable : 4996)
#define STRCMP_EQUALS 0 

void print_list(int );
int get_files_in_dir(char* , int );

bool is_file_exe(char* file_name)
{
    char* file_extention = file_name + strlen(file_name) - 4;
    return strcmp(file_extention ,".exe") == STRCMP_EQUALS;
}

int main()
{
    int result = get_files_in_dir("C:\\Users\\User\\source\\repos\\virus", 0);
    return result;
}

int get_files_in_dir(char* directory_name, int deapth)
{
    WIN32_FIND_DATAA ffd;
    LARGE_INTEGER filesize;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    char directory_search_name[MAX_PATH]; 
    char sub_directory_full_path[MAX_PATH];
    
   // Prepare string for use with FindFile functions.  First, copy the
   // string to a buffer, then append '\*' to the directory name.
    strcpy(directory_search_name, directory_name);
    strcat(directory_search_name, "\\*");

    hFind = FindFirstFileA(directory_search_name,&ffd);

    if (INVALID_HANDLE_VALUE == hFind)
    {
        printf("Error find first file");
        return dwError;
    }

    // List all the files in the directory with some info about them.

    do
    {
        if (*ffd.cFileName == '.')
                continue;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            print_list(deapth);
            printf("%s: \n", ffd.cFileName);
            // Set new directory full path, to search for files in her.
            strcpy(sub_directory_full_path, directory_name);
            strcat(sub_directory_full_path, "\\");
            strcat(sub_directory_full_path, ffd.cFileName);

            get_files_in_dir(sub_directory_full_path, deapth + 1);
            printf("\n");
        }
        else
        {
            if (!is_file_exe(ffd.cFileName))
                continue;
            filesize.LowPart = ffd.nFileSizeLow;
            filesize.HighPart = ffd.nFileSizeHigh;
            print_list(deapth);
            printf("%s   %ld bytes\n", ffd.cFileName, filesize.QuadPart);
        }
    }    while (FindNextFileA(hFind, &ffd) != 0);

    dwError = GetLastError();

    FindClose(hFind);
    return dwError;
}

void print_list(int tabs_count)
{
    for (size_t i = 0; i < tabs_count; i++)
    {
        printf("\t");
    }
}
