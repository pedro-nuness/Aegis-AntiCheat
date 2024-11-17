#pragma once
#include <Windows.h>
#include <string>
#include <vector>


typedef struct _SYSTEM_HANDLE {
    ULONG       ProcessId;
    UCHAR       ObjectTypeNumber;
    UCHAR       Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
    BOOL ReferencingUs;
} SYSTEM_HANDLE , * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG         HandleCount;
    SYSTEM_HANDLE Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION , * PSYSTEM_HANDLE_INFORMATION;

struct ThreadInfo {
    DWORD threadID;
    DWORD ownerProcessID;
    int priority;
    FILETIME creationTime;
    FILETIME exitTime;
    FILETIME kernelTime;
    FILETIME userTime;
    HANDLE threadHandle;
    LPVOID stackAddress;
};

struct ModuleInfo {
    std::string moduleName;
    std::string modulePath;
    DWORD baseAddress;
    DWORD size;
    HANDLE moduleHandle;
};

struct ProcessInfo {
    DWORD processID;
    std::string processName;
    DWORD threadCount;
    DWORD priorityClass;
    std::vector<ModuleInfo> modules;
    std::vector<ThreadInfo> threads;
    std::vector< _SYSTEM_HANDLE> openhandles;
};
