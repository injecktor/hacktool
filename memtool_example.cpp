#include "memtool.hpp"

using namespace mem_tool;

int main() {
    printf("Started\n");
    auto proc_struct_ptr = std::make_shared<PROCESSENTRY32>(*find_process(_T("application.exe")));
    auto module_ptr = std::make_shared<MODULEENTRY32>(*mem_tool::find_module(proc_struct_ptr->th32ProcessID, _T("application.exe")));
    HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, static_cast<int>(NULL), proc_struct_ptr->th32ProcessID);
    string pattern = "11238459";
    string mask = "xxxx";
    pattern = str_to_hex_str(pattern);
    auto sig_addr = sig_scan(proc_handle, (BYTE*)0x1cfcaad2df0, 4, pattern, mask);
    printf("Address found: %p\n", sig_addr);
    CloseHandle(proc_handle);
    return 0;
}