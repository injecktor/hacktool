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

// char* mem_tool::sig_scan2(char* pattern, char* mask, char* begin, char* end, Process* process)
// {
// 	char* currentChunk = begin;
// 	SIZE_T bytesRead;

// 	while (currentChunk < end)
// 	{
// 		char buffer[4096]; //char * buffer[4096];?

// 		DWORD oldprotect;
// 		VirtualProtectEx(process->handle, currentChunk, sizeof(buffer), PROCESS_VM_READ, &oldprotect);
// 		ReadProcessMemory(process->handle, currentChunk, &buffer, sizeof(buffer), &bytesRead);
// 		VirtualProtectEx(process->handle, currentChunk, sizeof(buffer), oldprotect, NULL);

// 		if (bytesRead == 0)
// 		{
// 			return nullptr;
// 		}

// 		char* internalAddress = In::Scan(pattern, mask, (char*)&buffer, bytesRead);

// 		if (internalAddress != nullptr)
// 		{
// 			uintptr_t offsetFromBuffer = internalAddress - (char*)&buffer;
// 			return (currentChunk + offsetFromBuffer);
// 		}
// 		else
// 		{
// 			currentChunk = currentChunk + bytesRead;
// 		}
// 	}
// 	return nullptr;
// }

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

int main() {
    PROCESSENTRY32 process;
    const char *test_char = "\x74\x89\x11\x65\x74\x82\x82\x82\x33\x47\x89\x61";
    printf("Started\n");
    find_process(&process, _T("application.exe"));
    printf("Got process id: %d\n", process.th32ProcessID);
    printf("Pointer: %p\n", sig_scan((char*)test_char, 12, "\x33\x47\x88", "xx") - test_char);
    return 0;
}