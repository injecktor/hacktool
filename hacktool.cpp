#include "hacktool.hpp"

#define KBYTE 1024
#define ALIGN(_x, _base) ((_x / _base + 1) * _base)

#ifdef UNICODE
#define SF "%ls"
#else
#define SF "%s"
#endif

using namespace std;

static HWND wnd_handle;

namespace hacktool {

    MODULEENTRY32 target_proc_t::find_module(LPCTSTR module_name) {
        MODULEENTRY32 module_struct;
        module_struct.dwSize = sizeof(MODULEENTRY32);
        if (!has_id()) {
            return module_struct;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_proc_id);
        if (Module32First(snapshot, &module_struct)) {
#ifdef HACKTOOL_VERBAL
            printf("Module name: " SF ", id: %u\n", module_struct.szModule, module_struct.th32ModuleID);
#endif
            do {
                if (!_tcscmp(module_struct.szModule, module_name)) {
                    CloseHandle(snapshot);
                    return module_struct;
                }
            } while (Module32Next(snapshot, &module_struct));
        }
        CloseHandle(snapshot);
        return module_struct;
    }

    static BOOL CALLBACK enum_windows_callback(HWND handle, LPARAM process_id) {
        DWORD wnd_process_id;
        GetWindowThreadProcessId(handle, &wnd_process_id);
#ifdef HACKTOOL_VERBAL
        int length = GetWindowTextLength(handle);
        if (length) {
            _TCHAR* buffer = new _TCHAR[length + 1];
            GetWindowText(handle, buffer, length + 1);
            printf("Window name: " SF ", process id: %u, window handle: %u\n", buffer, wnd_process_id, handle);
            delete[] buffer;
        }
#endif
        if (static_cast<DWORD>(process_id) != wnd_process_id) {
            return TRUE;
        }
        wnd_handle = handle;
        return FALSE;
    }

    HWND target_proc_t::get_HWND() {
        wnd_handle = NULL;
        if (has_id()) {
            EnumWindows(enum_windows_callback, static_cast<LPARAM>(m_proc_id));
        }
        return wnd_handle;
    }

    bool target_proc_t::open_process(DWORD dwDesiredAccess, BOOL bInheritHandle) {
        if (!has_id()) {
            return false;
        }
        m_proc = OpenProcess(dwDesiredAccess, bInheritHandle, m_proc_id);
        if (!m_proc) {
            return false;
        }
        return true;
    }

    static BYTE* _sig_scan(PVOID begin, DWORD size, string pattern, string mask) {
        mask = trim(mask);
        size_t pattern_size = pattern.length();
        size_t mask_size = mask.length();
        if (mask_size > pattern_size || size < mask_size) {
            return nullptr;
        }
        for (DWORD i = 0; i < size - mask_size + 1; i++) {
            bool found = true;
            PBYTE ptr = reinterpret_cast<PBYTE>(begin) + i;
            for (DWORD j = 0; j < mask_size; j++) {
                if (static_cast<BYTE>(pattern[j]) != *(ptr + j) && mask[j] != '?') {
                    found = false;
                    break;
                }
            }
            if (found) {
                return ptr;
            }
        }
        return nullptr;
    }

    PVOID target_proc_t::sig_scan(PVOID begin, DWORD size, string pattern, string mask) {
        if (!has_handle()) {
            return nullptr;
        }
        auto current_chunk = reinterpret_cast<PBYTE>(begin);
        PBYTE end = reinterpret_cast<PBYTE>(begin) + size;
        BYTE buffer[KBYTE];
        DWORD count;
        while (current_chunk < end) {
            count = end - current_chunk > sizeof(buffer) ? sizeof(buffer) : end - current_chunk;

            SIZE_T bytes_readed = read_mem(current_chunk, count, buffer);
            if (bytes_readed == 0) {
                return nullptr;
            }

            BYTE* internal_address = _sig_scan(reinterpret_cast<BYTE*>(buffer), bytes_readed, pattern, mask);
            if (internal_address != nullptr) {
                uintptr_t offset_from_buffer = reinterpret_cast<uintptr_t>(internal_address) - reinterpret_cast<uintptr_t>(buffer);
                return current_chunk + offset_from_buffer;
            }
            else {
                current_chunk += bytes_readed;
            }
        }
        return nullptr;
    }

#ifdef INTERNAL
    SIZE_T target_proc_t::read_mem(PVOID address, DWORD count, PVOID buffer) {
        if (!has_handle()) {
            return 0;
        }
        auto addr = reinterpret_cast<PBYTE>(address);
        auto buf = reinterpret_cast<PBYTE>(buffer);
        for (size_t i = 0; i < count; i++) {
            buf[i] = addr[i];
        }
        return count;
    }

    SIZE_T target_proc_t::write_mem(PVOID address, DWORD count, PVOID buffer) {
        if (!has_handle()) {
            return 0;
        }
        auto addr = reinterpret_cast<PBYTE>(address);
        auto buf = reinterpret_cast<PBYTE>(buffer);
        for (size_t i = 0; i < count; i++) {
            addr[i] = buf[i];
        }
        return count;
    }
#else
    SIZE_T target_proc_t::read_mem(PVOID address, DWORD count, PVOID buffer) {
        if (!has_handle()) {
            return 0;
        }
        DWORD oldprotect;
        SIZE_T bytes_readed;
        if (!VirtualProtectEx(m_proc, address, count, PAGE_READWRITE, &oldprotect)) {
            return 0;
        }
        ReadProcessMemory(m_proc, address, buffer, count, &bytes_readed);
        VirtualProtectEx(m_proc, address, count, oldprotect, nullptr);
        return bytes_readed;
    }

    SIZE_T target_proc_t::write_mem(PVOID address, DWORD count, PVOID buffer) {
        if (!has_handle()) {
            return 0;
        }
        DWORD oldprotect;
        SIZE_T bytes_written;
        if (!VirtualProtectEx(m_proc, address, count, PAGE_READWRITE, &oldprotect)) {
            return 0;
        }
        WriteProcessMemory(m_proc, address, buffer, count, &bytes_written);
        VirtualProtectEx(m_proc, address, count, oldprotect, nullptr);
        return bytes_written;
    }
#endif

    SIZE_T target_proc_t::inject_dll(string dll_path) {
        if (!has_handle()) {
            return 0;
        }
        auto size = static_cast<SIZE_T>(filesystem::file_size(dll_path));
        SIZE_T aligned_size;
        if (!size) {
            return 0;
        }
        aligned_size = ALIGN(size, KBYTE);
        LPVOID lpHeapBaseAddress = VirtualAllocEx(m_proc, NULL, aligned_size, MEM_COMMIT, PAGE_READWRITE);
        if (!lpHeapBaseAddress) {
            return 0;
        }
        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(m_proc, lpHeapBaseAddress, dll_path.c_str(), size, &bytesWritten)) {
            return 0;
        }
        LPTHREAD_START_ROUTINE lpLoadLibraryStartAddress = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"));
        if (!CreateRemoteThread(m_proc, NULL, 0, lpLoadLibraryStartAddress,
            lpHeapBaseAddress, 0, NULL)) {
            return 0;
        }
        return bytesWritten;
    }

    PROCESSENTRY32 target_proc_t::find_process(LPCTSTR proc_name) {
        PROCESSENTRY32 proc_struct;
        proc_struct.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(snapshot, &proc_struct)) {
            do {
#ifdef HACKTOOL_VERBAL
                printf("Process name: " SF ", id: %u\n", proc_struct.szExeFile, proc_struct.th32ProcessID);
#endif
                if (!_tcscmp(proc_struct.szExeFile, proc_name)) {
                    CloseHandle(snapshot);
                    return proc_struct;
                }
            } while (Process32Next(snapshot, &proc_struct));
        }
        CloseHandle(snapshot);
        return proc_struct;
    }

    string trim(string str) {
        string result;
        size_t length = str.length();
        for (size_t i = 0; i < length; i++)
        {
            if (!std::isspace(str[i])) {
                result += str[i];
            }
        }
        return result;
    }

    string str_to_hex_str(string str) {
        string result;
        size_t length = str.length();
        if (length % 2 != 0) {
            return result;
        }
        for (size_t i = 0; i < length; i += 2) {
            result += (char)stoi(str.substr(i, 2), 0, 16);
        }
        return result;
    }

    vector3_t world_to_screen(const vector3_t& pos, view_matrix_t view_matrix, DWORD window_weight, DWORD window_height) {
        float x = view_matrix[0][0] * pos.x + view_matrix[0][1] * pos.y + view_matrix[0][2] * pos.z + view_matrix[0][3];
        float y = view_matrix[1][0] * pos.x + view_matrix[1][1] * pos.y + view_matrix[1][2] * pos.z + view_matrix[1][3];
        float w = view_matrix[3][0] * pos.x + view_matrix[3][1] * pos.y + view_matrix[3][2] * pos.z + view_matrix[3][3];

        if (w < 0.01f) {
            return { 0, 0, 0 };
        }

        x /= w;
        y /= w;

        float _x = window_weight * .5f;
        float _y = window_height * .5f;

        _x += .5f * x * window_weight + .5f;
        _y -= .5f * y * window_height + .5f;
        return { _x, _y, w };
    }

};
