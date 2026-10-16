package fsutil

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// ErrSnapshotNotRegular reports that a snapshot target exists but is a directory, symlink, FIFO, socket,
// or device rather than a regular file. Consumers detect it with errors.Is.
var ErrSnapshotNotRegular = errors.New("fsutil: snapshot target is not a regular file")

// ErrSnapshotTooLarge reports that a snapshot target's bytes exceed the caller's cap. Consumers detect
// it with errors.Is.
var ErrSnapshotTooLarge = errors.New("fsutil: snapshot target exceeds the byte cap")

// beforeSnapshotRead fires between the size check and the read, so a test can grow the target and
// exercise the guard that catches a file bigger than its own fstat reported. Production runs the no-op.
var beforeSnapshotRead = func() {}

// FileSnapshot is the state SnapshotFileAt observed through one descriptor. When Exists is false every
// other field is zero. Dev and Ino identify the inode the bytes and mode were read from, so a consumer
// restoring later can prove it is acting on that same file rather than on whatever now answers to the
// name.
type FileSnapshot struct {
	Exists bool
	Data   []byte
	Mode   os.FileMode
	Dev    uint64
	Ino    uint64
}

// SnapshotFileAt reads name under the already open directory parentDir and reports either that the entry
// is absent, or that it is a regular file together with its bytes, permission mode, and inode identity.
// Everything after the open — the type check, the size check, and the read — uses that one descriptor,
// so nothing is re-resolved by name between the check and the read and the bytes returned are the bytes
// of the inode that was checked.
//
// name must be a single path component. A symlink is refused rather than followed (O_NOFOLLOW), and any
// non-regular entry is refused with ErrSnapshotNotRegular. The open is non-blocking so a FIFO or device
// entry is refused instead of hanging the caller. A file whose bytes exceed maxBytes is refused with
// ErrSnapshotTooLarge: the pre-read size check rejects an already oversized entry without reading it,
// and the read itself stops one byte past the cap so a file that grows between the two still fails
// rather than returning a snapshot larger than the caller allowed.
func SnapshotFileAt(parentDir *os.File, name string, maxBytes int64) (FileSnapshot, error) {
	if !singleComponent(name) {
		return FileSnapshot{}, &os.PathError{Op: "openat", Path: name, Err: syscall.EINVAL}
	}
	if maxBytes < 0 {
		return FileSnapshot{}, &os.PathError{Op: "openat", Path: name, Err: syscall.EINVAL}
	}

	fd, oErr := unix.Openat(int(parentDir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if oErr != nil {
		if errors.Is(oErr, fs.ErrNotExist) {
			return FileSnapshot{}, nil
		}
		// O_NOFOLLOW turns a symlink into ELOOP, which is the refusal this helper owes its callers
		// rather than a generic open failure.
		if errors.Is(oErr, syscall.ELOOP) {
			return FileSnapshot{}, &os.PathError{Op: "openat", Path: name, Err: ErrSnapshotNotRegular}
		}
		return FileSnapshot{}, &os.PathError{Op: "openat", Path: name, Err: oErr}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close() //nolint:errcheck // read-only descriptor; the snapshot is already fully read

	var st unix.Stat_t
	if sErr := unix.Fstat(fd, &st); sErr != nil {
		return FileSnapshot{}, &os.PathError{Op: "fstat", Path: name, Err: sErr}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return FileSnapshot{}, &os.PathError{Op: "fstat", Path: name, Err: ErrSnapshotNotRegular}
	}
	if st.Size > maxBytes {
		return FileSnapshot{}, &os.PathError{Op: "read", Path: name, Err: ErrSnapshotTooLarge}
	}

	beforeSnapshotRead()

	// maxBytes+1 overflows to a negative limit at math.MaxInt64; at that cap no read can exceed it, so
	// the limit is unnecessary rather than merely unrepresentable.
	src := io.Reader(f)
	if maxBytes < math.MaxInt64 {
		src = io.LimitReader(f, maxBytes+1)
	}
	data, rErr := io.ReadAll(src)
	if rErr != nil {
		return FileSnapshot{}, &os.PathError{Op: "read", Path: name, Err: rErr}
	}
	if int64(len(data)) > maxBytes {
		return FileSnapshot{}, &os.PathError{Op: "read", Path: name, Err: ErrSnapshotTooLarge}
	}

	return FileSnapshot{
		Exists: true,
		Data:   data,
		Mode:   os.FileMode(st.Mode).Perm(),
		Dev:    uint64(st.Dev),
		Ino:    uint64(st.Ino),
	}, nil
}
