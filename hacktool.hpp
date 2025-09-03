#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <algorithm> 
#include <filesystem>
#include <memory>

namespace hacktool {
    class target_proc_t {
    public:
        target_proc_t(DWORD proc_id) : m_proc_id(proc_id) {};
        target_proc_t(HANDLE proc) : m_proc(proc), m_proc_id(GetProcessId(m_proc)) {};

        //// Section of functions those are proc_id enough

        MODULEENTRY32 find_module(LPCTSTR module_name);
        // If process has several windows the function returns first found
        HWND get_window_handle();

        //// Section of functions those are HANDLE need

        // Pattern must be hex string
        BYTE* sig_scan(PVOID begin, DWORD size, string pattern, string mask);

        SIZE_T read_mem(PVOID address, DWORD count, PVOID buffer);
        SIZE_T write_mem(PVOID address, DWORD count, PVOID buffer);

        template<typename T>
        T read_mem(PVOID address) {
            T buf;
            read_mem(address, sizeof(T), &buf);
            return buf;
        }

        template<typename T>
        void write_mem(PVOID address, const T& data) {
            T buf;
            write_mem(address, sizeof(T), &data);
            return buf;
        }

        // Process must have PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, 
        // PROCESS_VM_WRITE, and PROCESS_VM_READ rights
        // Returns written bytes count
        SIZE_T inject_dll(string dll_path);


    private:
        bool has_handle();
        bool has_id();

        HANDLE m_proc = nullptr;
        DWORD m_proc_id = 0;
    };

    extern PROCESSENTRY32 find_process(LPCTSTR proc_name);
    extern string trim(string str);

    // Converts "48e1a6B0" into "\x48\xe1\xa6\xB0"
    // Input must be even-length
    extern string str_to_hex_str(string str);
}