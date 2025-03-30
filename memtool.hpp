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
    extern shared_ptr<PROCESSENTRY32> find_process(LPCTSTR proc_name);
    extern shared_ptr<MODULEENTRY32> find_module(DWORD process_id, LPCTSTR module_name);
    extern string trim(string str);
    // Pattern must be hex string
    extern BYTE* sig_scan(PVOID begin, DWORD size, string pattern, string mask);
    extern BYTE* sig_scan(HANDLE process, PVOID begin, DWORD size, string pattern, string mask);
    // Process have to have PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, 
    // PROCESS_VM_WRITE, and PROCESS_VM_READ rights
    // Returns written bytes count
    extern SIZE_T inject_dll(HANDLE process, string dll_path);
    // Converts "48e1a6B0" into "\x48\xe1\xa6\xB0"
    // Input must be even-length
    extern string str_to_hex_str(string str);
    extern SIZE_T read_mem(HANDLE process, PVOID address, DWORD count, PVOID buffer);
    extern SIZE_T write_mem(HANDLE process, PVOID address, DWORD count, PVOID buffer);
    extern HWND GetWindowHandle(DWORD process_id);
}