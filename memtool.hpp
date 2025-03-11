#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <algorithm> 

using namespace std;

namespace mem_tool {
    void find_process(PROCESSENTRY32 *proc_struct, LPCTSTR proc_name);
    string trim(string str);
    char* sig_scan(char *begin, DWORD size, string pattern, string mask);
    char* sig_scan(HANDLE process, char *begin, DWORD size, string pattern, string mask);
    // Input must be even-length
    string str_to_hex_str(string str);
}