#include "memtool.hpp"

using namespace mem_tool;

int main() {
    printf("Started\n");
    auto proc_struct_ptr = std::make_shared<PROCESSENTRY32>(*find_process(_T("application.exe")));
    // HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_struct_ptr->th32ProcessID);
    // string pattern = "554889e54883ec30e832010000ba05000000b903000000e8b3ffffff8945fcba05000000b903000000e871ffffff8945f88b45fc89c2488d054e7b00004889c1e8";
    // pattern = str_to_hex_str(pattern);
    // string mask = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    // char *sig_addr = sig_scan(proc_handle, _T("application.exe"), 332 * 1024, pattern, mask);
    // printf("Address found: %p", sig_addr);
    // CloseHandle(proc_handle);

    auto module_ptr = mem_tool::find_module(proc_struct_ptr->th32ProcessID, _T("KERNEL32.DLL"));
    printf("Module ptr: %p\n", module_ptr);
    if (module_ptr) {
        printf("szModule: %ls\n", module_ptr->szModule);
        printf("szExePath: %ls\n", module_ptr->szExePath);
        delete module_ptr;
    }
    return 0;
}