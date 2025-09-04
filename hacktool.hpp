#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <algorithm> 
#include <filesystem>
#include <memory>

namespace hacktool {
    struct view_matrix_t {
        float matrix[4][4];
        view_matrix_t() {
            for (size_t i = 0; i < 4; i++) {
                for (size_t j = 0; j < 4; j++) {
                    matrix[i][j] = 0;
                }
            }
        }
        view_matrix_t(const view_matrix_t& other) {
            for (size_t i = 0; i < 4; i++) {
                for (size_t j = 0; j < 4; j++) {
                    matrix[i][j] = other.matrix[i][j];
                }
            }
        }
        float* operator[](int index) {
            return matrix[index];
        }
    };

    struct vector3_t {
        float x = 0, y = 0, z = 0;
        vector3_t() = default;
        vector3_t(float x, float y, float z) : x(x), y(y), z(z) {};

        vector3_t operator+(const vector3_t& other) {
            return vector3_t(x + other.x, y + other.y, z + other.z);
        }
        vector3_t operator-(const vector3_t& other) {
            return vector3_t(x - other.x, y - other.y, z - other.z);
        }
        vector3_t operator*(const vector3_t& other) {
            return vector3_t(x * other.x, y * other.y, z * other.z);
        }
        vector3_t operator/(const vector3_t& other) {
            return vector3_t(x / other.x, y / other.y, z / other.z);
        }

        constexpr void operator+=(const vector3_t& other) {
            x += other.x;
            y += other.y;
            z += other.z;
        }
        constexpr void operator-=(const vector3_t& other) {
            x -= other.x;
            y -= other.y;
            z -= other.z;
        }
        constexpr void operator*=(const vector3_t& other) {
            x *= other.x;
            y *= other.y;
            z *= other.z;
        }
        constexpr void operator/=(const vector3_t& other) {
            x /= other.x;
            y /= other.y;
            z /= other.z;
        }

        vector3_t operator+(float num) {
            return vector3_t(x + num, y + num, z + num);
        }
        vector3_t operator-(float num) {
            return vector3_t(x - num, y - num, z - num);
        }
        vector3_t operator*(float num) {
            return vector3_t(x * num, y * num, z * num);
        }
        vector3_t operator/(float num) {
            return vector3_t(x / num, y / num, z / num);
        }

        constexpr void operator+=(float num) {
            x += num;
            y += num;
            z += num;
        }
        constexpr void operator-=(float num) {
            x -= num;
            y -= num;
            z -= num;
        }
        constexpr void operator*=(float num) {
            x *= num;
            y *= num;
            z *= num;
        }
        constexpr void operator/=(float num) {
            x /= num;
            y /= num;
            z /= num;
        }

        constexpr bool operator<(const vector3_t& other) {
            if (x < other.x && y < other.y && z < other.z)
                return true;
            return false;
        }
        constexpr bool operator==(const vector3_t& other) {
            if (x == other.x && y == other.y && z == other.z)
                return true;
            return false;
        }
        constexpr bool operator<=(const vector3_t& other) {
            if (x <= other.x && y <= other.y && z <= other.z)
                return true;
            return false;
        }
    };

    class target_proc_t {
    public:
        target_proc_t() = default;
        target_proc_t(LPCTSTR proc_name) {
            set(proc_name);
        };
        target_proc_t(DWORD proc_id) {
            set(proc_id);
        };
        target_proc_t(HANDLE proc) {
            set(proc);
        };

        inline void set(LPCTSTR proc_name) {
            auto entry = find_process(proc_name);
            m_proc_id = entry.th32ProcessID;
        }
        inline void set(DWORD proc_id) {
            m_proc_id = proc_id;
        }
        inline void set(HANDLE proc) {
            m_proc = proc;
            m_proc_id = GetProcessId(m_proc);
        }
        inline DWORD get_proc_id() {
            return m_proc_id;
        }
        inline HANDLE get_proc() {
            return m_proc;
        }

        inline bool has_handle() {
            if (m_proc == nullptr)
                return false;
            return true;
        }

        inline bool has_id() {
            if (m_proc_id == 0)
                return false;
            return true;
        }

        //// Section of functions those are proc_id enough

        MODULEENTRY32 find_module(LPCTSTR module_name);

        // If process has several windows the function returns first found
        HWND get_HWND();

        bool open_process(DWORD dwDesiredAccess, BOOL bInheritHandle);

        //// Section of functions those are HANDLE need

        // Pattern must be hex string
        PVOID sig_scan(PVOID begin, DWORD size, std::string pattern, std::string mask);

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
        SIZE_T inject_dll(std::string dll_path);

    private:
        PROCESSENTRY32 find_process(LPCTSTR proc_name);

        HANDLE m_proc = nullptr;
        DWORD m_proc_id = 0;
    };

    extern std::string trim(std::string str);

    // Converts "48e1a6B0" into "\x48\xe1\xa6\xB0"
    // Input must be even-length
    extern std::string str_to_hex_str(std::string str);

    extern vector3_t world_to_screen(const vector3_t& pos, view_matrix_t view_matrix, DWORD window_weight, DWORD window_height);
};