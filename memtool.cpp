#include "memtool.hpp"

#define KBYTE 1024
#define ALIGN(_x, _base) ((_x / _base + 1) * _base)

using namespace mem_tool;
using namespace std;

PROCESSENTRY32* mem_tool::find_process(LPCTSTR proc_name) {
    PROCESSENTRY32 *proc_struct = new PROCESSENTRY32;
    proc_struct->dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, proc_struct)) {
        do {
            if (!_tcscmp(proc_struct->szExeFile, proc_name)) {
                CloseHandle(snapshot);
                return proc_struct;
            }
        } while (Process32Next(snapshot, proc_struct));
    }

    CloseHandle(snapshot);
    return nullptr;
}

MODULEENTRY32* mem_tool::find_module(DWORD process_id, LPCTSTR module_name) {
    MODULEENTRY32 *module_struct = new MODULEENTRY32;
    module_struct->dwSize = sizeof(MODULEENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
    if (Module32First(snapshot, module_struct)) {
        do {
            if (!_tcscmp(module_struct->szModule, module_name)) {
                CloseHandle(snapshot);
                return module_struct;
            }
        } while (Module32Next(snapshot, module_struct));
    }
    CloseHandle(snapshot);
    return nullptr;
}

string mem_tool::trim(string str) {
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

BYTE* mem_tool::sig_scan(BYTE *begin, DWORD size, string pattern, string mask) {
    mask = mem_tool::trim(mask);
    size_t pattern_size = pattern.length();
    size_t mask_size = mask.length();
    if (mask_size > pattern_size || size < mask_size) {
        return nullptr;
    }
    for (DWORD i = 0; i < size - mask_size + 1; i++) {
        bool found = true;
        BYTE *ptr = begin + i;
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

BYTE* mem_tool::sig_scan(HANDLE process, BYTE *begin, DWORD size, string pattern, string mask) {
    BYTE* current_chunk = begin;
    BYTE* end = begin + size;
    BYTE buffer[KBYTE];
    DWORD count;
    while (current_chunk < end) {
        count = end - current_chunk > sizeof(buffer) ? sizeof(buffer) : end - current_chunk;

        SIZE_T bytes_readed = read_mem(process, current_chunk, count, buffer);
        if (bytes_readed == 0) {
            return nullptr;
        }

        BYTE *internal_address = sig_scan(reinterpret_cast<BYTE*>(buffer), bytes_readed, pattern, mask);
        if (internal_address != nullptr) {
            uintptr_t offset_from_buffer = reinterpret_cast<uintptr_t>(internal_address) - reinterpret_cast<uintptr_t>(buffer);
            return current_chunk + offset_from_buffer;
        } else {
            current_chunk += bytes_readed;
        }
    }
    return nullptr;
}

SIZE_T mem_tool::inject_dll(HANDLE process, string dll_path) {
    SIZE_T size = filesystem::file_size(dll_path);
    SIZE_T aligned_size;
    if (!size) {
        return 0;
    }
    aligned_size = ALIGN(size, KBYTE);
    LPVOID lpHeapBaseAddress = VirtualAllocEx(process, NULL, aligned_size, MEM_COMMIT, PAGE_READWRITE);
    if (!lpHeapBaseAddress) {
        return 0;
    }
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(process, lpHeapBaseAddress, dll_path.c_str(), size, &bytesWritten)) {
        return 0;
    }
    LPTHREAD_START_ROUTINE lpLoadLibraryStartAddress = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"));
    if (!CreateRemoteThread(process, NULL, 0, lpLoadLibraryStartAddress, 
                lpHeapBaseAddress, 0, NULL)) {
        return 0;
    }
    return bytesWritten;
}

string mem_tool::str_to_hex_str(string str) {
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

SIZE_T mem_tool::read_mem(HANDLE process, BYTE *address, DWORD count, BYTE *buffer) {
    DWORD oldprotect;
    SIZE_T bytes_readed;
    if (!VirtualProtectEx(process, address, count, PROCESS_VM_READ, &oldprotect)) {
        return 0;
    }
    ReadProcessMemory(process, address, buffer, count, &bytes_readed);
    VirtualProtectEx(process, address, count, oldprotect, NULL);
    return bytes_readed;
}

SIZE_T mem_tool::write_mem(HANDLE process, BYTE *address, DWORD count, BYTE *buffer) {
    DWORD oldprotect;
    SIZE_T bytes_written;
    if (!VirtualProtectEx(process, address, count, PROCESS_VM_READ, &oldprotect)) {
        return 0;
    }
    WriteProcessMemory(process, address, buffer, count, &bytes_written);
    VirtualProtectEx(process, address, count, oldprotect, NULL);
    return bytes_written;
}
