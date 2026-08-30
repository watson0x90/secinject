## Section Mapping Process Injection (secinject): Cobalt Strike BOF

> **This is a patched fork of [apokryptein/secinject](https://github.com/apokryptein/secinject).**
> Original technique and code by [@apokryptein](https://github.com/apokryptein);
> this fork applies OPSEC + robustness patches described in the
> [Fork Patches](#fork-patches) section below. Upstream credits and technique
> attribution are preserved unchanged.

Beacon Object File (BOF) that leverages Native APIs to achieve process injection through memory section mapping. It implements two commands via an Aggressor Script: one to inject beacon shellcode for a selected listener into the desired process, and one to inject the user's desired shellcode - loaded from a bin file - into the desired process.  These are *sec-inject* and *sec-shinject* respectively.

- Currently, this is only implemented for x64 processes.

### How to Make
```
git clone https://github.com/watson0x90/secinject.git
cd secinject/src
make
```

Toolchain: `x86_64-w64-mingw32-gcc` (mingw-w64). Tested via WSL.

### How to Use
#### Injecting Beacon
```
sec-inject PID LISTENER-NAME
```

#### Injecting Other Shellcode
```
sec-shinject PID /path/to/bin
```

---

## Fork Patches

Two tagged patch series on top of upstream. The BOF binary at
`dist/secinject.x64.o` is rebuilt after each series so consumers can pull
straight from `git` without a local build environment.

### `patches-v1` — OPSEC + robustness fixes

Applied after a review flagged that the upstream BOF's userland-visible
signals were louder than the section-mapping technique itself justified.

| # | Fix | Was | Now |
|---|-----|-----|-----|
| 1 | Thread creation API | `KERNEL32$CreateRemoteThread` — the single most heavily EDR-hooked injection API | `NTDLL$NtCreateThreadEx` — one layer lower, hits a different userland hook set |
| 3 | Target-process rights | `PROCESS_ALL_ACCESS` (0x1FFFFF) — an ObjectAccess-audit red flag on `<injector> → <target>` | `PROCESS_CREATE_THREAD` \| `PROCESS_VM_OPERATION` \| `PROCESS_QUERY_LIMITED_INFORMATION` = 0x100A |
| 4 | Handle cleanup | `hRemoteProcess` and `hThread` leaked — inter-process handle correlation trail | Both `NtClose`d, plus cascading cleanup on every error path |
| 5 | Error handling | No checks on `OpenProcess` / `CreateRemoteThread` — silent failure or crash | `NTSTATUS` / `GetLastError` checked on every native call, reported via `CALLBACK_ERROR` |

Also cleaned up:
- `LARGE_INTEGER sectionSize` now uses `.QuadPart` (was `.LowPart`-only — safe for beacon shellcode < 4 GB, but wrong)
- `BeaconDataExtract` now gets `int*` (was `SIZE_T*` — silent truncation on x64)
- `baseAddrLocal` / `baseAddrRemote` typed `PVOID` (were `HANDLE` — same alias but wrong intent)

Symbol-table verification (`x86_64-w64-mingw32-objdump -t`):
`NtCreateThreadEx` present, `CreateRemoteThread` **gone** from imports.

### `patches-v3` — critical bugfix (current release)

**Anyone on `patches-v2` should upgrade.** The `patches-v2` [P5] "zero
the local view before unmap" step was destructive — the local view and
the remote view are two mappings of the SAME section pages, so zeroing
the local view also zeros what the target process sees. The injected
thread would then jump to NUL bytes and crash the target the instant
`NtCreateThreadEx` returned (reproduced by injecting into `notepad.exe`
— the process died immediately).

Fix:

- Removed the destructive `zero_fill_bytes(baseAddrLocal, ...)` call.
- The other two `[P5]` steps stay in — zeroing the beacon-owned
  shellcode buffer (a separate allocation, safe to scrub) and NULL'ing
  our local pointer.
- `NtUnmapViewOfSection(hLocalProcess, baseAddrLocal)` already removes
  our view; the target keeps its remote view. That alone is sufficient
  anti-forensics from our side.
- Code-site comment expanded with a correctness note so a future editor
  doesn't re-introduce the same bug.

No other changes — the technique class, the primitives (RWX section,
RX remote view, `NtCreateThreadEx` with HIDE_FROM_DEBUGGER, SEC_NO_CHANGE,
minimal target rights, NTSTATUS names, handle hygiene) are all unchanged.

### `patches-v2` — polish on top of patches-v1 (superseded by patches-v3)

> ⚠ **Do not use `patches-v2` in production** — see `patches-v3` above for
> the bugfix. Kept as a historical checkpoint.


Small, non-brittle improvements. None of these change the injection
technique class — the underlying section-mapping + `NtCreateThreadEx` flow
is unchanged.

| # | Fix | What it buys |
|---|-----|--------------|
| P1 | `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` (0x00000004) on `NtCreateThreadEx` | The new thread is invisible to any debugger attached to the target (`DbgUiRemoteBreakin` / `DebugActiveProcess` callbacks). Doesn't hide from EDR; hides from `x64dbg` / `WinDbg` + any inline debugger callback the target might have installed. |
| P2 | `SEC_NO_CHANGE` (0x00400000) on `NtCreateSection` — combined with `SEC_COMMIT` as `AllocationAttributes` | Blocks any subsequent `NtProtectVirtualMemory` call from changing the view protections after mapping. Defense-in-depth against EDRs that re-protect suspicious sections to memory-scan them. Initial view protections (PAGE_READWRITE local, PAGE_EXECUTE_READ remote) are set at map time, unaffected. |
| P3 | Symbolic `NTSTATUS` messages in every error path | A static helper (`ntstatus_str`) names the well-known codes an operator will actually see (`STATUS_ACCESS_DENIED (ACL / session mismatch / privilege gap)`, `STATUS_CONFLICTING_ADDRESSES`, `STATUS_QUOTA_EXCEEDED`, `STATUS_SECTION_TOO_BIG`, `STATUS_PROCESS_IS_TERMINATING`, etc.). Raw hex still prints alongside. |
| P5 | Anti-forensics scrubbing before unmap | Static zero-fill helper (`zero_fill_bytes`, byte-by-byte, no `MSVCRT$memset` dependency added). Before unmapping the local view: **1.** Zero the local view bytes. **2.** Zero the beacon-owned shellcode buffer `BeaconDataExtract` gave us (beacon frees it after we return but no reason to leave it live in the interim). **3.** NULL the local `shellcode` pointer. `baseAddrLocal` and `hSection` are also NULL'd after their respective cleanup for stack-frame hygiene. |

### Deliberately NOT patched (roadmap)

| # | Item | Why deferred |
|---|------|--------------|
| 2 | Section is `PAGE_EXECUTE_READWRITE` | Required so we can hold both a local RW view (for `memcpy`) and a remote RX view. Section-level protection is the ceiling for its views; narrowing the section breaks one of the two mappings. Real fix requires switching primitive (spawn-and-hollow or thread hijack — both have their own downsides). |
| 10 | No direct/indirect syscalls | Every `NTDLL$*` call still hits the userland ntdll stub, hookable by EDR. SysWhispers3 with `jumper_randomized` mode is the natural next patch. Deferred pending an environment where the failure mode (BOF crashing the beacon on a host with heavily-hooked ntdll) can be safely validated. |

### BOF size progression

| Tag | Bytes | Notes |
|-----|-------|-------|
| upstream | 3273 | apokryptein/secinject at fork point |
| `patches-v1` | 3498 | Thread swap + rights narrowing + error paths |
| `patches-v2` | 5809 | Adds NTSTATUS switch table + zero-fill helper + expanded format strings. **Superseded — do not use.** |
| `patches-v3` | ~5750 | Removes the destructive local-view scrub from patches-v2 [P5]. Byte-identical technique otherwise. **Current release.** |

### Symbol-table verification (post-patches-v3)

Post-`patches-v3`, `objdump -t dist/secinject.x64.o` shows:

- `__imp_KERNEL32$OpenProcess` — present
- `__imp_KERNEL32$GetLastError` — present (new in patches-v1)
- `__imp_NTDLL$NtCreateSection` — present
- `__imp_NTDLL$NtMapViewOfSection` — present
- `__imp_NTDLL$NtUnmapViewOfSection` — present
- `__imp_NTDLL$NtClose` — present
- `__imp_NTDLL$NtCreateThreadEx` — present (replaces `CreateRemoteThread` in patches-v1)
- `__imp_KERNEL32$CreateRemoteThread` — **gone** as of patches-v1

Plus two static helpers (`ntstatus_str`, `zero_fill_bytes`), no external imports.

---

### Code References
https://github.com/EspressoCake/Process_Protection_Level_BOF/

https://github.com/rsmudge/CVE-2020-0796-BOF/blob/master/src/libc.c

https://github.com/connormcgarr/cThreadHijack/

https://github.com/boku7/HOLLOW/

https://github.com/ajpc500/BOFs/
