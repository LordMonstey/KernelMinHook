#pragma once
#include <ntifs.h>
#include "KernelMinHook.h"

#define MEMORY_SLOT_SIZE 64

VOID InitializeBuffer(VOID);
VOID UninitializeBuffer(VOID);
PVOID AllocateBuffer(PVOID pOrigin);
VOID FreeBuffer(PVOID pBuffer);
BOOLEAN IsExecutableAddress(PVOID pAddress);
