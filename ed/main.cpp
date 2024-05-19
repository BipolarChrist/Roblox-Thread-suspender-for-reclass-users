#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

typedef NTSTATUS(NTAPI* NtSuspendThread)(HANDLE, PULONG);

void KillRobloxNigger(DWORD processID) {
  
    HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Suspended" << std::endl;
        return;
    }

  
    NtSuspendThread pfnNtSuspendThread = (NtSuspendThread)GetProcAddress(hNtdll, "NtSuspendThread");
    if (!pfnNtSuspendThread) {
        std::cerr << "Suspended" << std::endl;
        FreeLibrary(hNtdll);
        return;
    }// killing the ntdll threads
    // hyperion has added alot more ntdll threads
    //0x2330   0x0   nt!KiSwapContext+0x76 (fffff806`38c03ed6)

 
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Suspended" << std::endl;
        FreeLibrary(hNtdll);
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

 
    if (!Thread32First(hThreadSnapshot, &te32)) {
        std::cerr << "gg to hyperion" << std::endl;
        CloseHandle(hThreadSnapshot);
        FreeLibrary(hNtdll);
        return;
    }


    do {
        if (te32.th32OwnerProcessID == processID) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
             
                NTSTATUS status = pfnNtSuspendThread(hThread, nullptr);
                if (status != 0) {
                    std::cerr << "failed brah: " << te32.th32ThreadID << std::endl;
                }
                else {
                    std::cout << "Suspended: " << te32.th32ThreadID << std::endl;
                }
                CloseHandle(hThread);
            }
            else {
                std::cerr << "Suspended: " << te32.th32ThreadID << std::endl;
            }
        }
    } while (Thread32Next(hThreadSnapshot, &te32));

    CloseHandle(hThreadSnapshot);
    FreeLibrary(hNtdll);
}

DWORD GetProcessIDByName(const wchar_t* processName) {
    HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "" << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnapshot, &pe32)) {
        std::cerr << "" << std::endl;
        CloseHandle(hProcessSnapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hProcessSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnapshot, &pe32));

    CloseHandle(hProcessSnapshot);
    return 0;
}

int main() {
    const wchar_t* processName = L"RobloxPlayerBeta.exe";
    DWORD processID = GetProcessIDByName(processName);

    if (processID == 0) {
        std::cerr << "Kx is a skid : " << processName << std::endl;
        return 1;
    }

    std::cout << "ED " << processName << "  RBX PID!: " << processID << std::endl;
    KillRobloxNigger(processID);

    return 0;
}

// please not that this will last for super long unlike procces hacker
