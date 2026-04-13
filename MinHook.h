#pragma once

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
#error MinHook supports only x86 and x64 systems.
#endif

#include <ntifs.h>

#define UINT_MAX 0xFFFFFFFF

typedef unsigned int UINT;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long long UINT64;
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned char* LPBYTE;
typedef unsigned long* LPDWORD;

#ifndef WINAPI
#define WINAPI __stdcall
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum MINHOOK_STATUS
    {
        MH_UNKNOWN = -1,
        MH_OK = 0,
        MH_ERROR_ALREADY_INITIALIZED,
        MH_ERROR_NOT_INITIALIZED,
        MH_ERROR_ALREADY_CREATED,
        MH_ERROR_NOT_CREATED,
        MH_ERROR_ENABLED,
        MH_ERROR_DISABLED,
        MH_ERROR_NOT_EXECUTABLE,
        MH_ERROR_UNSUPPORTED_FUNCTION,
        MH_ERROR_MEMORY_ALLOC,
        MH_ERROR_MEMORY_PROTECT,
        MH_ERROR_MODULE_NOT_FOUND,
        MH_ERROR_FUNCTION_NOT_FOUND
    } MH_STATUS;

#define MH_ALL_HOOKS NULL

    MH_STATUS WINAPI MH_Initialize(VOID);
    MH_STATUS WINAPI MH_Uninitialize(VOID);
    MH_STATUS WINAPI MH_CreateHook(PVOID pTarget, PVOID pDetour, PVOID* ppOriginal);
    MH_STATUS WINAPI MH_RemoveHook(PVOID pTarget);
    MH_STATUS WINAPI MH_EnableHook(PVOID pTarget);
    MH_STATUS WINAPI MH_DisableHook(PVOID pTarget);
    MH_STATUS WINAPI MH_QueueEnableHook(PVOID pTarget);
    MH_STATUS WINAPI MH_QueueDisableHook(PVOID pTarget);
    MH_STATUS WINAPI MH_ApplyQueued(VOID);
    const char* WINAPI MH_StatusToString(MH_STATUS status);

#ifdef __cplusplus
}
#endif