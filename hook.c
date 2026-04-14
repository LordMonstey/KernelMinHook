#include <ntifs.h>
#include "KernelMinHook.h"
#include "buffer.h"
#include "trampoline.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#define INITIAL_HOOK_CAPACITY   32
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX
#define TAG_MINHOOK 'kniM'

typedef struct _HOOK_ENTRY {
    PVOID pTarget;
    PVOID pDetour;
    PVOID pTrampoline;
    UINT8  backup[8];
    UINT8  patchAbove : 1;
    UINT8  isEnabled : 1;
    UINT8  queueEnable : 1;
    UINT   nIP : 4;
    UINT8  oldIPs[8];
    UINT8  newIPs[8];
} HOOK_ENTRY, * PHOOK_ENTRY;

FAST_MUTEX g_fastMutex;
BOOLEAN g_isInitialized = FALSE;

struct {
    PHOOK_ENTRY pItems;
    UINT        capacity;
    UINT        size;
} g_hooks;

static UINT FindHookEntry(PVOID pTarget) {
    UINT i;
    for (i = 0; i < g_hooks.size; ++i) {
        if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pItems[i].pTarget)
            return i;
    }
    return INVALID_HOOK_POS;
}

static PHOOK_ENTRY AddHookEntry() {
    if (g_hooks.pItems == NULL) {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)ExAllocatePoolWithTag(NonPagedPool, g_hooks.capacity * sizeof(HOOK_ENTRY), TAG_MINHOOK);
        if (g_hooks.pItems == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity) {
        PHOOK_ENTRY p = (PHOOK_ENTRY)ExAllocatePoolWithTag(NonPagedPool, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY), TAG_MINHOOK);
        if (p == NULL)
            return NULL;

        RtlCopyMemory(p, g_hooks.pItems, g_hooks.capacity * sizeof(HOOK_ENTRY));
        ExFreePoolWithTag(g_hooks.pItems, TAG_MINHOOK);

        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

static VOID DeleteHookEntry(UINT pos) {
    if (pos < g_hooks.size - 1)
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];

    g_hooks.size--;

    if (g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size) {
        PHOOK_ENTRY p = (PHOOK_ENTRY)ExAllocatePoolWithTag(NonPagedPool, (g_hooks.capacity / 2) * sizeof(HOOK_ENTRY), TAG_MINHOOK);
        if (p == NULL)
            return;

        RtlCopyMemory(p, g_hooks.pItems, g_hooks.size * sizeof(HOOK_ENTRY));
        ExFreePoolWithTag(g_hooks.pItems, TAG_MINHOOK);

        g_hooks.capacity /= 2;
        g_hooks.pItems = p;
    }
}

static MH_STATUS EnableHookLL(UINT pos, BOOLEAN enable) {
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    SIZE_T patchSize = sizeof(JMP_REL);
    LPBYTE pPatchTarget = (LPBYTE)pHook->pTarget;

    if (pHook->patchAbove) {
        pPatchTarget -= sizeof(JMP_REL);
        patchSize += sizeof(JMP_REL_SHORT);
    }

    PMDL mdl = IoAllocateMdl(pPatchTarget, (ULONG)patchSize, FALSE, FALSE, NULL);
    if (!mdl) return MH_ERROR_MEMORY_PROTECT;

    MH_STATUS retStatus = MH_ERROR_MEMORY_PROTECT;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (mapping) {
            NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(status)) {
                if (enable) {
                    PJMP_REL pJmp = (PJMP_REL)mapping;
                    pJmp->opcode = 0xE9;
                    pJmp->operand = (UINT32)((LPBYTE)pHook->pDetour - (pPatchTarget + sizeof(JMP_REL)));

                    if (pHook->patchAbove) {
                        PJMP_REL_SHORT pShortJmp = (PJMP_REL_SHORT)mapping;
                        pShortJmp->opcode = 0xEB;
                        pShortJmp->operand = (UINT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
                    }
                }
                else {
                    if (pHook->patchAbove)
                        RtlCopyMemory(mapping, pHook->backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
                    else
                        RtlCopyMemory(mapping, pHook->backup, sizeof(JMP_REL));
                }
                retStatus = MH_OK;
            }
            MmUnmapLockedPages(mapping, mdl);
        }
        MmUnlockPages(mdl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        retStatus = MH_ERROR_MEMORY_PROTECT;
    }

    IoFreeMdl(mdl);

    if (retStatus == MH_OK) {
        pHook->isEnabled = enable;
        pHook->queueEnable = enable;
    }

    return retStatus;
}

static MH_STATUS EnableAllHooksLL(BOOLEAN enable) {
    MH_STATUS status = MH_OK;
    UINT i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i) {
        if (g_hooks.pItems[i].isEnabled != enable) {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS) {
        for (i = first; i < g_hooks.size; ++i) {
            if (g_hooks.pItems[i].isEnabled != enable) {
                status = EnableHookLL(i, enable);
                if (status != MH_OK)
                    break;
            }
        }
    }

    return status;
}

static VOID EnterSpinLock(VOID) {
    ExAcquireFastMutex(&g_fastMutex);
}

static VOID LeaveSpinLock(VOID) {
    ExReleaseFastMutex(&g_fastMutex);
}

MH_STATUS WINAPI MH_Initialize(VOID) {
    if (g_isInitialized)
        return MH_ERROR_ALREADY_INITIALIZED;

    ExInitializeFastMutex(&g_fastMutex);
    InitializeBuffer();
    g_isInitialized = TRUE;

    return MH_OK;
}

MH_STATUS WINAPI MH_Uninitialize(VOID) {
    MH_STATUS status = MH_OK;
    EnterSpinLock();

    if (g_isInitialized) {
        status = EnableAllHooksLL(FALSE);
        if (status == MH_OK) {
            UninitializeBuffer();
            if (g_hooks.pItems) {
                ExFreePoolWithTag(g_hooks.pItems, TAG_MINHOOK);
            }
            g_hooks.pItems = NULL;
            g_hooks.capacity = 0;
            g_hooks.size = 0;
            g_isInitialized = FALSE;
        }
    }
    else {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();
    return status;
}

MH_STATUS WINAPI MH_CreateHook(PVOID pTarget, PVOID pDetour, PVOID* ppOriginal) {
    MH_STATUS status = MH_OK;
    EnterSpinLock();

    if (g_isInitialized) {
        if (IsExecutableAddress(pTarget) && IsExecutableAddress(pDetour)) {
            UINT pos = FindHookEntry(pTarget);
            if (pos == INVALID_HOOK_POS) {
                PVOID pBuffer = AllocateBuffer(pTarget);
                if (pBuffer != NULL) {
                    TRAMPOLINE ct;
                    ct.pTarget = pTarget;
                    ct.pDetour = pDetour;
                    ct.pTrampoline = pBuffer;

                    if (CreateTrampolineFunction(&ct)) {
                        PHOOK_ENTRY pHook = AddHookEntry();
                        if (pHook != NULL) {
                            pHook->pTarget = ct.pTarget;
                            pHook->pDetour = ct.pRelay;
                            pHook->pTrampoline = ct.pTrampoline;
                            pHook->patchAbove = ct.patchAbove;
                            pHook->isEnabled = FALSE;
                            pHook->queueEnable = FALSE;
                            pHook->nIP = ct.nIP;
                            RtlCopyMemory(pHook->oldIPs, ct.oldIPs, ARRAYSIZE(ct.oldIPs));
                            RtlCopyMemory(pHook->newIPs, ct.newIPs, ARRAYSIZE(ct.newIPs));

                            if (ct.patchAbove) {
                                RtlCopyMemory(pHook->backup, (LPBYTE)pTarget - sizeof(JMP_REL), sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
                            }
                            else {
                                RtlCopyMemory(pHook->backup, pTarget, sizeof(JMP_REL));
                            }

                            if (ppOriginal != NULL)
                                *ppOriginal = pHook->pTrampoline;
                        }
                        else {
                            status = MH_ERROR_MEMORY_ALLOC;
                        }
                    }
                    else {
                        status = MH_ERROR_UNSUPPORTED_FUNCTION;
                    }

                    if (status != MH_OK) {
                        FreeBuffer(pBuffer);
                    }
                }
                else {
                    status = MH_ERROR_MEMORY_ALLOC;
                }
            }
            else {
                status = MH_ERROR_ALREADY_CREATED;
            }
        }
        else {
            status = MH_ERROR_NOT_EXECUTABLE;
        }
    }
    else {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();
    return status;
}

MH_STATUS WINAPI MH_RemoveHook(PVOID pTarget) {
    MH_STATUS status = MH_OK;
    EnterSpinLock();

    if (g_isInitialized) {
        UINT pos = FindHookEntry(pTarget);
        if (pos != INVALID_HOOK_POS) {
            if (g_hooks.pItems[pos].isEnabled) {
                status = EnableHookLL(pos, FALSE);
            }
            if (status == MH_OK) {
                FreeBuffer(g_hooks.pItems[pos].pTrampoline);
                DeleteHookEntry(pos);
            }
        }
        else {
            status = MH_ERROR_NOT_CREATED;
        }
    }
    else {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();
    return status;
}

static MH_STATUS EnableHook(PVOID pTarget, BOOLEAN enable) {
    MH_STATUS status = MH_OK;
    EnterSpinLock();

    if (g_isInitialized) {
        if (pTarget == MH_ALL_HOOKS) {
            status = EnableAllHooksLL(enable);
        }
        else {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS) {
                if (g_hooks.pItems[pos].isEnabled != enable) {
                    status = EnableHookLL(pos, enable);
                }
                else {
                    status = enable ? MH_ERROR_ENABLED : MH_ERROR_DISABLED;
                }
            }
            else {
                status = MH_ERROR_NOT_CREATED;
            }
        }
    }
    else {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();
    return status;
}

MH_STATUS WINAPI MH_EnableHook(PVOID pTarget) {
    return EnableHook(pTarget, TRUE);
}

MH_STATUS WINAPI MH_DisableHook(PVOID pTarget) {
    return EnableHook(pTarget, FALSE);
}

static MH_STATUS QueueHook(PVOID pTarget, BOOLEAN queueEnable) {
    MH_STATUS status = MH_OK;
    EnterSpinLock();

    if (g_isInitialized) {
        if (pTarget == MH_ALL_HOOKS) {
            UINT i;
            for (i = 0; i < g_hooks.size; ++i)
                g_hooks.pItems[i].queueEnable = queueEnable;
        }
        else {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS) {
                g_hooks.pItems[pos].queueEnable = queueEnable;
            }
            else {
                status = MH_ERROR_NOT_CREATED;
            }
        }
    }
    else {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();
    return status;
}

MH_STATUS WINAPI MH_QueueEnableHook(PVOID pTarget) {
    return QueueHook(pTarget, TRUE);
}

MH_STATUS WINAPI MH_QueueDisableHook(PVOID pTarget) {
    return QueueHook(pTarget, FALSE);
}

MH_STATUS WINAPI MH_ApplyQueued(VOID) {
    MH_STATUS status = MH_OK;
    UINT i, first = INVALID_HOOK_POS;
    EnterSpinLock();

    if (g_isInitialized) {
        for (i = 0; i < g_hooks.size; ++i) {
            if (g_hooks.pItems[i].isEnabled != g_hooks.pItems[i].queueEnable) {
                first = i;
                break;
            }
        }

        if (first != INVALID_HOOK_POS) {
            for (i = first; i < g_hooks.size; ++i) {
                PHOOK_ENTRY pHook = &g_hooks.pItems[i];
                if (pHook->isEnabled != pHook->queueEnable) {
                    status = EnableHookLL(i, pHook->queueEnable);
                    if (status != MH_OK)
                        break;
                }
            }
        }
    }
    else {
        status = MH_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();
    return status;
}

const char* WINAPI MH_StatusToString(MH_STATUS status) {
    return "(unknown)";
}
