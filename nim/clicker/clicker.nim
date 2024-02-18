import winim/[lean, winstr, utils]
import std/[strformat, strutils]

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


proc sCreateProcess(target: string, pi: LPPROCESS_INFORMATION, si: LPSTARTUPINFOW | LPSTARTUPINFOEXW, creationFlags: DWORD = 0, args: string) =
    echo("[+] CreateProcessW")
    var cmdline = target & " " & args
    let ret = CreateProcessW(newWideCString(target),
                             newWideCString(cmdline),
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

proc sSpawnProcess(target: string, parent: int, pi: LPPROCESS_INFORMATION, args: string) = 
    var si: STARTUPINFOEXW
    ZeroMemory(addr si, sizeof(STARTUPINFOEXW))
    var attributeSize: SIZE_T
    var hParent: HANDLE
    var attrCount = 1 + (parent > 0)

    var ret: WINBOOL
    InitializeProcThreadAttributeList(NULL, attrCount, 0, addr attributeSize)
    var lpAttributeList = newSeq[byte](attributeSize)
    si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](addr lpAttributeList[0])
    ret = InitializeProcThreadAttributeList(si.lpAttributeList, attrCount, 0, &attributeSize)
    if ret == 0:
        panic("InitializeProcThreadAttributeList")
    var PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000
    var lpMitigationPolicy = addr(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
    ret = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, lpMitigationPolicy, sizeof(lpMitigationPolicy[]), NULL, NULL)
    if ret == 0:
        panic("UpdateProcThreadAttribute Mitigation Policy")

    if parent > 0:
        hParent = OpenProcess(MAXIMUM_ALLOWED, false, cast[DWORD](parent))
        if hParent == 0:
            panic("OpenProcess")

        # Using defer inside an if block would cause the defered statement to be executed at the end of the if block, which is not ideal for our scenario

        ret = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, addr hParent, sizeof(hParent), NULL, NULL)
        if ret == 0:
            panic("UpdateProcThreadAttribute PPID Spoofing")
    defer:
        if hParent != 0:
            echo("[+] Closing parent process handle")
            CloseHandle(hParent)
    si.StartupInfo.cb = cast[DWORD](sizeof(STARTUPINFOEXW))
    sCreateProcess(target, pi, addr si, CREATE_NEW_CONSOLE or EXTENDED_STARTUPINFO_PRESENT, args)

proc display(file: string, parent: int, args: string) =
    echo(fmt"[*] File: {file}")
    echo(fmt"[*] PPID Spoofing: {parent}")
    echo(fmt"[*] Args: {args}")
    echo()

proc clicker(file: string, parent = 0, args: seq[string]) =
    echo("Process Injector 3 (Wrapper): Clicker (Process Mitigation Policy)")
    var args_str = join(args, " ")
    display(file, parent, args_str)
    var pi: PROCESS_INFORMATION
    sSpawnProcess(file, parent, addr pi, args_str)
    echo(fmt"    PID: {pi.dwProcessId}")

when isMainModule:
    import cligen; dispatch clicker, help={
        "file": "Absolute file path to be executed",
        "parent": "Spoof the --file process under a Parent Process ID",
        "help": "Display help screen manual",
        "args": "-- args"
    }
