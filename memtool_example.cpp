#include "memtool.hpp"

using namespace mem_tool;

int main() {
    PROCESSENTRY32 process;
    printf("Started\n");
    find_process(&process, _T("application.exe"));
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, process.th32ProcessID);
    string pattern = "554889e54883ec30e832010000ba05000000b903000000e8b3ffffff8945fcba05000000b903000000e871ffffff8945f88b45fc89c2488d054e7b00004889c1e8";
    pattern = str_to_hex_str(pattern);
    string mask = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    // char *sig_addr = sig_scan(hProcess, _T("application.exe"), 332 * 1024, pattern, mask);
    // printf("Address found: %p", sig_addr);
    CloseHandle(hProcess);
    return 0;
}