// Copyright 2019 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fs

import (
	"context"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

// LoopbackNodeFd is a filesystem node in a loopback file system. It is
// public so it can be used as a basis for other loopback based
// filesystems. See NewLoopbackFile or LoopbackRoot for more
// information.
type LoopbackNodeFd struct {
	Inode

	mu           sync.Mutex
	fdSaved      int64
	statAtAccess syscall.Stat_t
}

func newChildLoopbackFdNode(parent *Inode, name string, st *syscall.Stat_t) *Inode {
	node := &LoopbackNodeFd{statAtAccess: *st}
	return parent.NewInode(context.Background(), node, StableAttr{Mode: st.Mode, Ino: st.Ino, Gen: 1})
}

// LoopbackNodeFdEmbedder can only be implemented by the LoopbackNodeFd
// concrete type.
type loopbackFdNodeEmbedder interface {
	LoopbackNodeFd() *LoopbackNodeFd
}

func (n *LoopbackNodeFd) LoopbackNodeFd() *LoopbackNodeFd {
	return n
}

func (n *LoopbackNodeFd) parentFd() (int, string, error) {
	name, parent := n.Parent()
	if parent == nil {
		return 0, "", syscall.ENOENT
	}
	parentLoopback, ok := parent.Operations().(loopbackFdNodeEmbedder)
	if !ok {
		return 0, "", syscall.ENOENT
	}
	fd, err := parentLoopback.LoopbackNodeFd().fd()
	if err != nil {
		return 0, "", err
	}
	return fd, name, nil
}

func (n *LoopbackNodeFd) parentFdOrSelf() (int, string, error) {
	fd, err := n.fdIfAvailable()
	if err == nil {
		return fd, "", err
	}
	return n.parentFd()
}

func (n *LoopbackNodeFd) fd() (int, error) {
	if n == nil {
		return 0, nil
	}
	fd := int(atomic.LoadInt64(&n.fdSaved))
	if fd <= 0 {
		n.mu.Lock()
		defer n.mu.Unlock()
		fd = int(atomic.LoadInt64(&n.fdSaved))
		if fd <= 0 {
			isDir := n.statAtAccess.Mode&syscall.S_IFMT == syscall.S_IFDIR
			flags := unix.O_CLOEXEC | unix.O_NOFOLLOW
			if isDir {
				flags |= unix.O_DIRECTORY
			} else {
				flags |= unix.O_PATH
			}
			parentFd, name, err := n.parentFd()
			if err != nil {
				return 0, err
			}
			fd, err = unix.Openat(parentFd, name, flags, 0)
			if err != nil {
				return 0, err
			}
			atomic.StoreInt64(&n.fdSaved, int64(fd))
			// Save the stat at access time, so we know the type.
			if err := syscall.Fstat(fd, &n.statAtAccess); err != nil {
				syscall.Close(fd)
				return 0, err
			}
		}
	}
	return fd, nil
}

func (n *LoopbackNodeFd) fdIfAvailable() (int, error) {
	if n == nil {
		return 0, nil
	}
	fd := int(atomic.LoadInt64(&n.fdSaved))
	if fd <= 0 {
		return 0, syscall.ENOENT
	}
	return fd, nil
}

var _ = (NodeStatfser)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	fd, err := n.fd()
	if err != nil {
		return ToErrno(err)
	}
	s := syscall.Statfs_t{}
	err = syscall.Fstatfs(fd, &s)
	if err != nil {
		return ToErrno(err)
	}
	out.FromStatfsT(&s)
	return OK
}

var _ = (NodeLookuper)((*LoopbackNodeFd)(nil))

var steps = prometheus.NewSummaryVec(
	prometheus.SummaryOpts{
		Name: "velda_fuse_lookup_steps",
		Help: "Time spent in each step of the FUSE lookup operation",
	},
	[]string{"step"},
)

func init() {
	prometheus.MustRegister(steps)
}
func (n *LoopbackNodeFd) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	t1 := time.Now()
	fd, err := n.fd()
	if err != nil {
		return nil, ToErrno(err)
	}

	t2 := time.Now()
	st := syscall.Stat_t{}
	err = syscall.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	t3 := time.Now()
	if err != nil {
		log.Printf("Lookup %s %s failed: %v", n.Path(nil), name, err)
		steps.WithLabelValues("lookup_fail").Observe(float64(t2.Sub(t1).Seconds()))
		steps.WithLabelValues("fstatat_fail").Observe(float64(t3.Sub(t2).Seconds()))
		return nil, ToErrno(err)
	}

	out.Attr.FromStat(&st)
	node := newChildLoopbackFdNode(&n.Inode, name, &st)
	t4 := time.Now()
	steps.WithLabelValues("lookup").Observe(float64(t2.Sub(t1).Seconds()))
	steps.WithLabelValues("fstatat").Observe(float64(t3.Sub(t2).Seconds()))
	steps.WithLabelValues("newInode").Observe(float64(t4.Sub(t3).Seconds()))
	return node, 0
}

// preserveOwner sets uid and gid of `name` according to the caller information
// in `ctx`.
func (n *LoopbackNodeFd) preserveOwner(ctx context.Context, fd int, name string) error {
	if os.Getuid() != 0 {
		return nil
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil
	}
	return syscall.Fchownat(fd, name, int(caller.Uid), int(caller.Gid), unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH)
}

var _ = (NodeMknoder)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Mknod(ctx context.Context, name string, mode, rdev uint32, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	fd, err := n.fd()
	if err != nil {
		return nil, ToErrno(err)
	}
	err = syscall.Mknodat(fd, name, mode, intDev(rdev))
	if err != nil {
		return nil, ToErrno(err)
	}
	n.preserveOwner(ctx, fd, name)
	st := syscall.Stat_t{}
	if err := syscall.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
		unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
		return nil, ToErrno(err)
	}

	out.Attr.FromStat(&st)

	node := &LoopbackNodeFd{statAtAccess: st}
	ch := n.NewInode(ctx, node, StableAttr{Mode: st.Mode, Ino: st.Ino, Gen: 1})

	return ch, 0
}

var _ = (NodeMkdirer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	fd, err := n.fd()
	if err != nil {
		return nil, ToErrno(err)
	}
	err = unix.Mkdirat(fd, name, mode)
	if err != nil {
		return nil, ToErrno(err)
	}
	n.preserveOwner(ctx, fd, name)
	st := syscall.Stat_t{}
	if err := syscall.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
		unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
		return nil, ToErrno(err)
	}

	out.Attr.FromStat(&st)

	ch := newChildLoopbackFdNode(&n.Inode, name, &st)

	return ch, 0
}

var _ = (NodeRmdirer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Rmdir(ctx context.Context, name string) syscall.Errno {
	fd, err := n.fd()
	if err != nil {
		return ToErrno(err)
	}
	err = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
	return ToErrno(err)
}

var _ = (NodeUnlinker)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Unlink(ctx context.Context, name string) syscall.Errno {
	fd, err := n.fd()
	if err != nil {
		return ToErrno(err)
	}
	err = unix.Unlinkat(fd, name, 0)
	return ToErrno(err)
}

var _ = (NodeRenamer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Rename(ctx context.Context, name string, newParent InodeEmbedder, newName string, flags uint32) syscall.Errno {
	e2, ok := newParent.(loopbackFdNodeEmbedder)
	if !ok {
		return syscall.EXDEV
	}

	if e2.LoopbackNodeFd().statAtAccess.Dev != n.statAtAccess.Dev {
		return syscall.EXDEV
	}

	fd1, err := n.fd()
	if err != nil {
		return ToErrno(err)
	}
	fd2, err := e2.LoopbackNodeFd().fd()
	if err != nil {
		return ToErrno(err)
	}

	err = unix.Renameat2(fd1, name, fd2, newName, uint(flags))
	return ToErrno(err)
}

var _ = (NodeCreater)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *Inode, fh FileHandle, fuseFlags uint32, errno syscall.Errno) {
	parentFd, err := n.fd()
	if err != nil {
		return nil, nil, 0, ToErrno(err)
	}
	flags = flags &^ syscall.O_APPEND
	fd, err := syscall.Openat(parentFd, name, int(flags)|os.O_CREATE, mode)
	if err != nil {
		return nil, nil, 0, ToErrno(err)
	}
	n.preserveOwner(ctx, fd, name)
	st := syscall.Stat_t{}
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, nil, 0, ToErrno(err)
	}

	ch := newChildLoopbackFdNode(&n.Inode, name, &st)
	lf := NewLoopbackFile(fd)

	out.FromStat(&st)
	return ch, lf, 0, 0
}

var _ = (NodeSymlinker)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	fd, err := n.fd()
	if err != nil {
		return nil, ToErrno(err)
	}
	err = unix.Symlinkat(target, fd, name)
	if err != nil {
		return nil, ToErrno(err)
	}
	n.preserveOwner(ctx, fd, name)
	st := syscall.Stat_t{}
	if err := syscall.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
		unix.Unlinkat(fd, name, 0)
		return nil, ToErrno(err)
	}
	ch := newChildLoopbackFdNode(&n.Inode, name, &st)

	out.Attr.FromStat(&st)
	return ch, 0
}

var _ = (NodeLinker)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Link(ctx context.Context, target InodeEmbedder, name string, out *fuse.EntryOut) (*Inode, syscall.Errno) {
	var newTargetFd int
	if e, ok := target.(loopbackFdNodeEmbedder); ok {
		var err error
		newTargetFd, err = e.LoopbackNodeFd().fd()
		if err != nil {
			return nil, ToErrno(err)
		}
	}
	fd, err := n.fd()
	if err != nil {
		return nil, ToErrno(err)
	}
	err = unix.Linkat(fd, name, newTargetFd, name, 0)
	if err != nil {
		return nil, ToErrno(err)
	}
	st := syscall.Stat_t{}
	if err := syscall.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
		unix.Unlinkat(fd, name, 0)
		return nil, ToErrno(err)
	}
	ch := newChildLoopbackFdNode(&n.Inode, name, &st)

	out.Attr.FromStat(&st)
	return ch, 0
}

var _ = (NodeReadlinker)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	parentFd, name, err := n.parentFd()
	if err != nil {
		return nil, ToErrno(err)
	}

	for l := 256; ; l *= 2 {
		buf := make([]byte, l)
		sz, err := unix.Readlinkat(parentFd, name, buf)
		if err != nil {
			return nil, ToErrno(err)
		}

		if sz < len(buf) {
			return buf[:sz], 0
		}
	}
}

var _ = (NodeOpener)((*LoopbackNodeFd)(nil))

// Symlink-safe through use of OpenSymlinkAware.
func (n *LoopbackNodeFd) Open(ctx context.Context, flags uint32) (fh FileHandle, fuseFlags uint32, errno syscall.Errno) {
	flags = flags &^ (syscall.O_APPEND | O_EXEC)
	parentFd, name, err := n.parentFd()
	if err != nil {
		return nil, 0, ToErrno(err)
	}

	f, err := unix.Openat(parentFd, name, int(flags)|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, ToErrno(err)
	}
	lf := NewLoopbackFile(f)
	return lf, 0, 0
}

var _ = (NodeOpendirHandler)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) OpendirHandle(ctx context.Context, flags uint32) (FileHandle, uint32, syscall.Errno) {
	fdparent, name, err := n.parentFd()
	if err != nil {
		return nil, 0, ToErrno(err)
	}
	fd, err := unix.Openat(fdparent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, 0, ToErrno(err)
	}
	stream, errno := NewLoopbackDirStreamFd(fd)
	return stream, 0, errno
}

var _ = (NodeReaddirer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Readdir(ctx context.Context) (DirStream, syscall.Errno) {
	fdparent, name, err := n.parentFd()
	if err != nil {
		return nil, ToErrno(err)
	}
	fd, err := unix.Openat(fdparent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, ToErrno(err)
	}
	return NewLoopbackDirStreamFd(fd)
}

var _ = (NodeGetattrer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Getattr(ctx context.Context, f FileHandle, out *fuse.AttrOut) syscall.Errno {
	if f != nil {
		if fga, ok := f.(FileGetattrer); ok {
			return fga.Getattr(ctx, out)
		}
	}

	st := syscall.Stat_t{}
	parentFd, name, err := n.parentFdOrSelf()
	if err != nil {
		return ToErrno(err)
	}
	err = syscall.Fstatat(parentFd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH)

	if err != nil {
		return ToErrno(err)
	}
	out.FromStat(&st)
	return OK
}

var _ = (NodeSetattrer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Setattr(ctx context.Context, f FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	fsa, ok := f.(FileSetattrer)
	parentFd, name, err := n.parentFdOrSelf()
	if ok && fsa != nil {
		fsa.Setattr(ctx, in, out)
	} else {
		if err != nil {
			return ToErrno(err)
		}
		if m, ok := in.GetMode(); ok {
			if err := unix.Fchmodat(parentFd, name, m, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
				return ToErrno(err)
			}
		}

		uid, uok := in.GetUID()
		gid, gok := in.GetGID()
		if uok || gok {
			suid := -1
			sgid := -1
			if uok {
				suid = int(uid)
			}
			if gok {
				sgid = int(gid)
			}
			if err := unix.Fchownat(parentFd, name, suid, sgid, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
				return ToErrno(err)
			}
		}

		mtime, mok := in.GetMTime()
		atime, aok := in.GetATime()

		if mok || aok {
			ta := unix.Timespec{Nsec: unix_UTIME_OMIT}
			tm := unix.Timespec{Nsec: unix_UTIME_OMIT}
			var err error
			if aok {
				ta, err = unix.TimeToTimespec(atime)
				if err != nil {
					return ToErrno(err)
				}
			}
			if mok {
				tm, err = unix.TimeToTimespec(mtime)
				if err != nil {
					return ToErrno(err)
				}
			}
			ts := []unix.Timespec{ta, tm}
			if err := unix.UtimesNanoAt(parentFd, name, ts, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH); err != nil {
				return ToErrno(err)
			}
		}

		/*
			if sz, ok := in.GetSize(); ok {
				if err := syscall.Truncate(p, int64(sz)); err != nil {
					return ToErrno(err)
				}
			}
		*/
	}

	fga, ok := f.(FileGetattrer)
	if ok && fga != nil {
		fga.Getattr(ctx, out)
	} else {
		st := syscall.Stat_t{}
		err := syscall.Fstatat(parentFd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH)
		if err != nil {
			return ToErrno(err)
		}
		out.FromStat(&st)
	}
	return OK
}

var _ = (NodeGetxattrer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	return 0, syscall.ENOSYS
	fd, err := n.fd()
	if err != nil {
		return 0, ToErrno(err)
	}
	sz, err := unix.Fgetxattr(fd, attr, dest)
	return uint32(sz), ToErrno(err)
}

var _ = (NodeSetxattrer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	fd, err := n.fd()
	if err != nil {
		return ToErrno(err)
	}
	err = unix.Fsetxattr(fd, attr, data, int(flags))
	return ToErrno(err)
}

var _ = (NodeRemovexattrer)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) Removexattr(ctx context.Context, attr string) syscall.Errno {
	fd, err := n.fd()
	if err != nil {
		return ToErrno(err)
	}
	err = unix.Fremovexattr(fd, attr)
	return ToErrno(err)
}

var _ = (NodeCopyFileRanger)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) CopyFileRange(ctx context.Context, fhIn FileHandle,
	offIn uint64, out *Inode, fhOut FileHandle, offOut uint64,
	len uint64, flags uint64) (uint32, syscall.Errno) {
	lfIn, ok := fhIn.(*loopbackFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	lfOut, ok := fhOut.(*loopbackFile)
	if !ok {
		return 0, unix.ENOTSUP
	}
	signedOffIn := int64(offIn)
	signedOffOut := int64(offOut)
	doCopyFileRange(lfIn.fd, signedOffIn, lfOut.fd, signedOffOut, int(len), int(flags))
	return 0, syscall.ENOSYS
}

var _ = (NodeOnForgetter)((*LoopbackNodeFd)(nil))

func (n *LoopbackNodeFd) OnForget() {
	// Close the file descriptor if it is still open.
	fd := int(atomic.SwapInt64(&n.fdSaved, 0))
	if fd > 0 {
		syscall.Close(fd)
	}
}

// NewLoopbackRoot returns a root node for a loopback file system whose
// root is at the given root. This node implements all NodeXxxxer
// operations available.
func NewLoopbackFdRoot(rootPath string) (InodeEmbedder, error) {
	var st syscall.Stat_t
	fd, err := unix.Openat(unix.AT_FDCWD, rootPath, unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	err = syscall.Stat(rootPath, &st)
	if err != nil {
		return nil, err
	}

	node := &LoopbackNodeFd{
		fdSaved:      int64(fd),
		statAtAccess: st,
	}
	return node, nil
}
