#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <algorithm> 
#include <filesystem>
#include <memory>

using namespace std;

namespace mem_tool {
    // !!This function allocates memory for PROCESSENTRY32
    PROCESSENTRY32* find_process(LPCTSTR proc_name);
    // !!This function allocates memory for MODULEENTRY32
    MODULEENTRY32* find_module(DWORD process_id, LPCTSTR module_name);
    string trim(string str);
    // Pattern must be hex string
    char* sig_scan(char *begin, DWORD size, string pattern, string mask);
    char* sig_scan(HANDLE process, char *begin, DWORD size, string pattern, string mask);
    // Process have to have PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, 
    // PROCESS_VM_WRITE, and PROCESS_VM_READ rights
    // Returns written bytes count
    SIZE_T inject_dll(HANDLE process, string dll_path);
    // Input must be even-length
    string str_to_hex_str(string str);
}