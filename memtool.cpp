#include "memtool.hpp"

using namespace mem_tool;
using namespace std;

void mem_tool::find_process(PROCESSENTRY32 *proc_struct, LPCTSTR proc_name) {
    proc_struct->dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, proc_struct))
    {
        do {
            if (!_tcscmp(proc_struct->szExeFile, proc_name)) {
                return;
            }
        } while (Process32Next(snapshot, proc_struct));
    }

    CloseHandle(snapshot);
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
    return str;
}

char* mem_tool::sig_scan(char *begin, DWORD size, string pattern, string mask) {
    mask = mem_tool::trim(mask);
    pattern = mem_tool::trim(pattern);
    size_t pattern_size = pattern.length();
    size_t mask_size = mask.length();
    if (mask_size > pattern_size) {
        return nullptr;
    }
	for (DWORD i = 0; i < size - pattern_size; i++) {
		bool found = true;
        char *ptr = begin + i;
		for (DWORD j = 0; j < mask_size; j++) {
			if (pattern[j] != *(ptr + j) && mask[j] != '?') {
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

char* mem_tool::sig_scan(HANDLE process, char *begin, DWORD size, string pattern, string mask) {
	char* current_chunk = begin;
    char* end = begin + size;
	SIZE_T bytesRead;

	while (current_chunk < end) {
		char buffer[4096];

		DWORD oldprotect;
		if (!VirtualProtectEx(process, current_chunk, sizeof(buffer), PROCESS_VM_READ, &oldprotect)) {
            return nullptr;
        }
		ReadProcessMemory(process, current_chunk, &buffer, sizeof(buffer), &bytesRead);
		VirtualProtectEx(process, current_chunk, sizeof(buffer), oldprotect, NULL);

		if (bytesRead == 0) {
			return nullptr;
		}

		char *internal_address = sig_scan((char*)&buffer, bytesRead, pattern, mask);

		if (internal_address != nullptr) {
			uintptr_t offset_from_buffer = internal_address - (char*)&buffer;
			return current_chunk + offset_from_buffer;
		} else {
			current_chunk += bytesRead;
		}
	}
	return nullptr;
}

string mem_tool::str_to_hex_str(string str) {
    string result;
    size_t length = str.length();
    if (length % 2 != 0) {
        return result;
    }
    for (size_t i = 0; i < length; i += 2) {
        string tmp = str.substr(i, 2);
        result += (char)stoi(str.substr(i, 2), 0, 16);
    }
    return result;
}

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