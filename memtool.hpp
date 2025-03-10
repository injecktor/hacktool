#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <algorithm> 

using namespace std;

namespace mem_tool {
    void find_process(PROCESSENTRY32 *proc_struct, LPCTSTR proc_name);
    char* sig_scan(char *begin, DWORD size, string pattern, string mask);
    string trim(string str);
}