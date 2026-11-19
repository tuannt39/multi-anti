//go:build windows

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	lockPollInterval = 10 * time.Millisecond

	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002

	errAccessDenied     syscall.Errno = 5
	errSharingViolation syscall.Errno = 32
	errLockViolation    syscall.Errno = 33

	movefileReplaceExisting = 0x00000001
	movefileWriteThrough    = 0x00000008

	aclRevision                      = 2
	objectInheritAce                 = 0x1
	containerInheritAce              = 0x2
	fileAllAccess                    = 0x001F01FF
	seFileObject                     = 1
	daclSecurityInformation          = 0x00000004
	protectedDaclSecurityInformation = 0x80000000
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
	procMoveFileExW  = kernel32.NewProc("MoveFileExW")

	procInitializeAcl         = advapi32.NewProc("InitializeAcl")
	procAddAccessAllowedAceEx = advapi32.NewProc("AddAccessAllowedAceEx")
	procSetNamedSecurityInfoW = advapi32.NewProc("SetNamedSecurityInfoW")
)

// EnsurePrivateDir creates path if absent and restricts its DACL to the current token user.
func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return setOwnerOnlyACL(path, true)
}

func applyFilePermissions(path string, secret bool) error {
	if !secret {
		return nil
	}
	return setOwnerOnlyACL(path, false)
}

func setOwnerOnlyACL(path string, isDir bool) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("get token user: %w", err)
	}
	if tu.User.Sid == nil {
		return errors.New("token user SID is nil")
	}

	sidLen := tu.User.Sid.Len()
	// ACL header (8) + ACCESS_ALLOWED_ACE up to SidStart (8) + SID bytes, 4-byte aligned.
	aclSize := (8 + 8 + sidLen + 3) &^ 3
	aclBuf := make([]byte, aclSize)

	r1, _, callErr := procInitializeAcl.Call(
		uintptr(unsafe.Pointer(&aclBuf[0])),
		uintptr(len(aclBuf)),
		aclRevision,
	)
	if r1 == 0 {
		return fmt.Errorf("InitializeAcl: %w", callErr)
	}

	var aceFlags uintptr
	if isDir {
		aceFlags = objectInheritAce | containerInheritAce
	}
	r1, _, callErr = procAddAccessAllowedAceEx.Call(
		uintptr(unsafe.Pointer(&aclBuf[0])),
		aclRevision,
		aceFlags,
		fileAllAccess,
		uintptr(unsafe.Pointer(tu.User.Sid)),
	)
	if r1 == 0 {
		return fmt.Errorf("AddAccessAllowedAceEx: %w", callErr)
	}

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// SetNamedSecurityInfoW returns a Win32 error code directly (0 on success).
	ret, _, _ := procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		seFileObject,
		daclSecurityInformation|protectedDaclSecurityInformation,
		0,
		0,
		uintptr(unsafe.Pointer(&aclBuf[0])),
		0,
	)
	runtime.KeepAlive(tu)
	runtime.KeepAlive(aclBuf)
	runtime.KeepAlive(pathPtr)
	if ret != 0 {
		return fmt.Errorf("SetNamedSecurityInfoW: %w", syscall.Errno(ret))
	}
	return nil
}

func acquireFileLock(ctx context.Context, f *os.File, shared bool) error {
	flags := uintptr(lockfileFailImmediately)
	if !shared {
		flags |= lockfileExclusiveLock
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var ol syscall.Overlapped
		r1, _, callErr := procLockFileEx.Call(
			f.Fd(),
			flags,
			0,
			1,
			0,
			uintptr(unsafe.Pointer(&ol)),
		)
		runtime.KeepAlive(&ol)
		if r1 != 0 {
			return nil
		}
		if !errors.Is(callErr, errLockViolation) {
			return callErr
		}

		timer := time.NewTimer(lockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func releaseFileLock(f *os.File) error {
	var ol syscall.Overlapped
	r1, _, callErr := procUnlockFileEx.Call(
		f.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ol)),
	)
	runtime.KeepAlive(&ol)
	if r1 == 0 {
		return callErr
	}
	return nil
}

func replaceFile(tmpPath, dstPath string) error {
	srcPtr, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		return err
	}
	dstPtr, err := syscall.UTF16PtrFromString(dstPath)
	if err != nil {
		return err
	}

	backoff := 10 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		r1, _, callErr := procMoveFileExW.Call(
			uintptr(unsafe.Pointer(srcPtr)),
			uintptr(unsafe.Pointer(dstPtr)),
			movefileReplaceExisting|movefileWriteThrough,
		)
		runtime.KeepAlive(srcPtr)
		runtime.KeepAlive(dstPtr)
		if r1 != 0 {
			return nil
		}
		lastErr = callErr
		// Retry briefly when Windows Defender or search indexing transiently holds the temp file.
		if !errors.Is(callErr, errSharingViolation) && !errors.Is(callErr, errAccessDenied) {
			return callErr
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	return lastErr
}

// ProjectDir makes linkPath mirror targetDir using an unprivileged NTFS directory junction (mklink /J).
func ProjectDir(targetDir, linkPath string) error {
	info, err := os.Stat(targetDir)
	if err != nil {
		return fmt.Errorf("stat target dir %q: %w", targetDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("target %q is not a directory", targetDir)
	}

	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}
	absLink, err := filepath.Abs(linkPath)
	if err != nil {
		return err
	}
	absTarget = filepath.FromSlash(filepath.Clean(absTarget))
	absLink = filepath.FromSlash(filepath.Clean(absLink))

	if err := os.MkdirAll(filepath.Dir(absLink), 0o700); err != nil {
		return err
	}

	existing, err := os.Lstat(absLink)
	if err == nil {
		if cur, readErr := os.Readlink(absLink); readErr == nil {
			if strings.EqualFold(filepath.Clean(cur), absTarget) {
				return nil
			}
			if err := os.Remove(absLink); err != nil {
				return err
			}
		} else if existing.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(absLink); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("destination %q exists and is not a reparse point", absLink)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if strings.ContainsAny(absLink+absTarget, "\"\r\n") {
		return fmt.Errorf("mklink /J path contains unsupported quote or newline")
	}
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: fmt.Sprintf(`cmd.exe /c mklink /J "%s" "%s"`, absLink, absTarget),
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J %q -> %q: %w (%s)", absLink, absTarget, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ProjectFile makes linkPath mirror targetFile using a hardlink, falling back to an atomic copy across volumes.
func ProjectFile(targetFile, linkPath string) error {
	targetInfo, err := os.Stat(targetFile)
	if err != nil {
		return fmt.Errorf("stat target file %q: %w", targetFile, err)
	}
	if targetInfo.IsDir() {
		return fmt.Errorf("target %q is a directory, want file", targetFile)
	}

	if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
		return err
	}

	existing, err := os.Lstat(linkPath)
	if err == nil {
		if os.SameFile(targetInfo, existing) {
			return nil
		}
		if existing.IsDir() {
			return fmt.Errorf("destination %q exists and is a directory", linkPath)
		}
		if err := os.Remove(linkPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.Link(targetFile, linkPath); err == nil {
		return nil
	}

	data, err := os.ReadFile(targetFile)
	if err != nil {
		return fmt.Errorf("read target file %q for copy fallback: %w", targetFile, err)
	}
	return WriteFileAtomic(linkPath, data, true)
}
