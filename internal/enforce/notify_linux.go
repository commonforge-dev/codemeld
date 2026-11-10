package enforce

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type seccompNotification struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Nr    int32
	Arch  uint32
	IP    uint64
	Args  [6]uint64
}

type seccompNotificationResponse struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

func recvNotification(listener int) (seccompNotification, error) {
	var n seccompNotification
	if err := notifyIoctl(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n)); err != nil {
		return seccompNotification{}, err
	}
	return n, nil
}

func sendNotificationResponse(listener int, resp seccompNotificationResponse) error {
	return notifyIoctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp))
}

func notificationIDValid(listener int, id uint64) error {
	return notifyIoctl(listener, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&id))
}

func notifyIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	return errnoErr(e)
}
