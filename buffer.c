#include <ntifs.h>
#include "buffer.h"

#define SCAN_RANGE 0x2000000 
#define MAX_CAVES 64

typedef struct _CAVE_SLOT {
    PVOID pAddress;
    BOOLEAN bUsed;
} CAVE_SLOT;

CAVE_SLOT g_Caves[MAX_CAVES];

VOID InitializeBuffer(VOID) {
    RtlZeroMemory(g_Caves, sizeof(g_Caves));
}

VOID UninitializeBuffer(VOID) {
    RtlZeroMemory(g_Caves, sizeof(g_Caves));
}

PVOID AllocateBuffer(PVOID pOrigin) {
    ULONG_PTR base = ((ULONG_PTR)pOrigin) & ~0xFFFll;
    ULONG_PTR start = (base > SCAN_RANGE) ? base - SCAN_RANGE : 0xFFFF800000000000ll;
    ULONG_PTR end = base + SCAN_RANGE;

    for (ULONG_PTR addr = base; addr > start; addr -= PAGE_SIZE) {
        if (!MmIsAddressValid((PVOID)addr)) continue;
        ULONG match = 0;
        __try {
            UCHAR* p = (UCHAR*)addr;
            for (ULONG i = 0; i < PAGE_SIZE; i++) {
                if (p[i] == 0xCC) {
                    match++;
                    if (match >= MEMORY_SLOT_SIZE) {
                        PVOID pCave = (PVOID)(&p[i - MEMORY_SLOT_SIZE + 1]);
                        BOOLEAN bAlreadyUsed = FALSE;
                        for (int c = 0; c < MAX_CAVES; c++) {
                            if (g_Caves[c].pAddress == pCave && g_Caves[c].bUsed) {
                                bAlreadyUsed = TRUE;
                                break;
                            }
                        }
                        if (!bAlreadyUsed) {
                            for (int c = 0; c < MAX_CAVES; c++) {
                                if (!g_Caves[c].bUsed) {
                                    g_Caves[c].pAddress = pCave;
                                    g_Caves[c].bUsed = TRUE;
                                    return pCave;
                                }
                            }
                        }
                    }
                }
                else {
                    match = 0;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
    }

    for (ULONG_PTR addr = base; addr < end; addr += PAGE_SIZE) {
        if (!MmIsAddressValid((PVOID)addr)) continue;
        ULONG match = 0;
        __try {
            UCHAR* p = (UCHAR*)addr;
            for (ULONG i = 0; i < PAGE_SIZE; i++) {
                if (p[i] == 0xCC) {
                    match++;
                    if (match >= MEMORY_SLOT_SIZE) {
                        PVOID pCave = (PVOID)(&p[i - MEMORY_SLOT_SIZE + 1]);
                        BOOLEAN bAlreadyUsed = FALSE;
                        for (int c = 0; c < MAX_CAVES; c++) {
                            if (g_Caves[c].pAddress == pCave && g_Caves[c].bUsed) {
                                bAlreadyUsed = TRUE;
                                break;
                            }
                        }
                        if (!bAlreadyUsed) {
                            for (int c = 0; c < MAX_CAVES; c++) {
                                if (!g_Caves[c].bUsed) {
                                    g_Caves[c].pAddress = pCave;
                                    g_Caves[c].bUsed = TRUE;
                                    return pCave;
                                }
                            }
                        }
                    }
                }
                else {
                    match = 0;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
    }
    return NULL;
}

VOID FreeBuffer(PVOID pBuffer) {
    for (int c = 0; c < MAX_CAVES; c++) {
        if (g_Caves[c].pAddress == pBuffer) {
            g_Caves[c].bUsed = FALSE;
            PMDL mdl = IoAllocateMdl(pBuffer, MEMORY_SLOT_SIZE, FALSE, FALSE, NULL);
            if (mdl) {
                __try {
                    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                    PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
                    if (mapping) {
                        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
                        if (NT_SUCCESS(status)) {
                            RtlFillMemory(mapping, MEMORY_SLOT_SIZE, 0xCC);
                        }
                        MmUnmapLockedPages(mapping, mdl);
                    }
                    MmUnlockPages(mdl);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                }
                IoFreeMdl(mdl);
            }
            break;
        }
    }
}

BOOLEAN IsExecutableAddress(PVOID pAddress) {
    return (BOOLEAN)MmIsAddressValid(pAddress);
}