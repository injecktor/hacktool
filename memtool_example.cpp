#include "memtool.hpp"
#include <psapi.h>

using namespace mem_tool;

int __stdcall my_func(int a, int b) {
    printf("My func\n");
    return a + b;
}

int main() {
    auto handle = get_window_handle(14460);
    printf("handle: %u\n", handle);
    return 0;
}