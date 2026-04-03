package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// setupMounts creates an isolated rootfs with only allowed paths visible.
func setupMounts(profile *Profile, projectDir, homeDir, username string) error {
	// Make the entire mount tree private so our changes don't propagate
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}

	// Create a tmpfs for the new rootfs
	rootfs := "/tmp/bnpm-root"
	if err := os.MkdirAll(rootfs, 0755); err != nil {
		return fmt.Errorf("mkdir rootfs: %w", err)
	}
	if err := unix.Mount("tmpfs", rootfs, "tmpfs", 0, "size=64m,mode=0755"); err != nil {
		return fmt.Errorf("mount tmpfs rootfs: %w", err)
	}

	// Create directory skeleton
	skelDirs := []string{
		"usr", "lib", "bin", "sbin", "etc", "etc/ssl", "etc/ssl/certs",
		"dev", "dev/pts", "dev/shm", "dev/net",
		"proc", "sys", "tmp", "var/tmp", "run",
	}

	// Add lib64 if it exists on host
	if isDir("/lib64") {
		skelDirs = append(skelDirs, "lib64")
	}

	// Add home directory path
	if homeDir != "" {
		skelDirs = append(skelDirs, strings.TrimPrefix(homeDir, "/"))
	}

	// Add project directory path
	skelDirs = append(skelDirs, strings.TrimPrefix(projectDir, "/"))

	// Add profile bind mount targets
	for _, bm := range profile.Filesystem.Binds {
		tgt := expandPath(bm.Target)
		if tgt != "" && tgt != "/" {
			skelDirs = append(skelDirs, strings.TrimPrefix(tgt, "/"))
		}
	}

	for _, d := range skelDirs {
		if err := os.MkdirAll(filepath.Join(rootfs, d), 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// Bind mount system directories (read-only)
	sysBinds := []string{"/usr", "/lib", "/bin", "/sbin"}
	if isDir("/lib64") {
		sysBinds = append(sysBinds, "/lib64")
	}
	for _, src := range sysBinds {
		if err := bindMountRO(rootfs, src, src); err != nil {
			return fmt.Errorf("bind %s: %w", src, err)
		}
	}

	// Set up /etc with selective content
	if err := setupEtc(rootfs, profile, homeDir, username); err != nil {
		return fmt.Errorf("setup /etc: %w", err)
	}

	// Device nodes (bind mount from host since mknod fails in user ns)
	devs := []string{"null", "zero", "urandom", "random"}
	for _, dev := range devs {
		dst := filepath.Join(rootfs, "dev", dev)
		if err := touchFile(dst); err != nil {
			return fmt.Errorf("touch /dev/%s: %w", dev, err)
		}
		if err := unix.Mount("/dev/"+dev, dst, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind /dev/%s: %w", dev, err)
		}
	}

	// /dev/net/tun for TAP device (needed for filtered network mode)
	if profile.Network.Mode == "filtered" {
		tunDst := filepath.Join(rootfs, "dev/net/tun")
		if err := touchFile(tunDst); err == nil {
			// Best effort — may not be available
			unix.Mount("/dev/net/tun", tunDst, "", unix.MS_BIND, "")
		}
	}

	// devpts for pseudo-terminals
	if err := unix.Mount("devpts", filepath.Join(rootfs, "dev/pts"), "devpts",
		0, "newinstance,ptmxmode=0666"); err != nil {
		// Non-fatal: some operations work without devpts
		fmt.Fprintf(os.Stderr, "bnpm: warning: devpts mount failed: %v\n", err)
	} else {
		// Create /dev/ptmx -> /dev/pts/ptmx symlink
		os.Symlink("pts/ptmx", filepath.Join(rootfs, "dev/ptmx"))
	}

	// /dev/shm
	unix.Mount("tmpfs", filepath.Join(rootfs, "dev/shm"), "tmpfs", 0, "size=64m")

	// procfs
	if err := unix.Mount("proc", filepath.Join(rootfs, "proc"), "proc", 0, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}

	// tmpfs for /tmp and /var/tmp
	if err := unix.Mount("tmpfs", filepath.Join(rootfs, "tmp"), "tmpfs", 0, "size=512m,mode=1777"); err != nil {
		return fmt.Errorf("mount /tmp: %w", err)
	}
	unix.Mount("tmpfs", filepath.Join(rootfs, "var/tmp"), "tmpfs", 0, "size=256m,mode=1777")

	// /run as tmpfs
	unix.Mount("tmpfs", filepath.Join(rootfs, "run"), "tmpfs", 0, "size=64m")

	// Project directory (read-write)
	if err := bindMountRW(rootfs, projectDir, projectDir); err != nil {
		return fmt.Errorf("bind project dir %s: %w", projectDir, err)
	}

	// Profile-specific bind mounts
	for _, bm := range profile.Filesystem.Binds {
		src := expandPath(bm.Source)
		tgt := expandPath(bm.Target)
		if bm.Optional && !pathExists(src) {
			continue
		}
		if bm.Create {
			os.MkdirAll(src, 0755)
		}
		if !pathExists(src) {
			if bm.Optional {
				continue
			}
			return fmt.Errorf("bind mount source %s does not exist", src)
		}
		os.MkdirAll(filepath.Join(rootfs, tgt), 0755)
		if bm.Mode == "ro" {
			if err := bindMountRO(rootfs, src, tgt); err != nil {
				if bm.Optional {
					continue
				}
				return fmt.Errorf("bind mount %s -> %s: %w", src, tgt, err)
			}
		} else {
			if err := bindMountRW(rootfs, src, tgt); err != nil {
				if bm.Optional {
					continue
				}
				return fmt.Errorf("bind mount %s -> %s: %w", src, tgt, err)
			}
		}
	}

	// pivot_root: requires the new root to be a mount point
	// It already is (tmpfs), so we can proceed directly
	oldroot := filepath.Join(rootfs, ".oldroot")
	if err := os.MkdirAll(oldroot, 0755); err != nil {
		return fmt.Errorf("mkdir oldroot: %w", err)
	}
	if err := unix.PivotRoot(rootfs, oldroot); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}

	// Unmount and remove old root
	if err := unix.Unmount("/.oldroot", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount oldroot: %w", err)
	}
	os.RemoveAll("/.oldroot")

	return nil
}

// setupEtc populates /etc in the new rootfs with minimal required content.
func setupEtc(rootfs string, profile *Profile, homeDir, username string) error {
	etcDir := filepath.Join(rootfs, "etc")

	// resolv.conf
	var resolv string
	switch profile.Network.Mode {
	case "filtered":
		// Point to the TAP gateway where our DNS proxy runs
		resolv = "nameserver 10.0.2.1\n"
	default:
		// No network — provide localhost (will fail, which is correct)
		resolv = "nameserver 127.0.0.1\n"
	}
	if err := os.WriteFile(filepath.Join(etcDir, "resolv.conf"), []byte(resolv), 0644); err != nil {
		return err
	}

	// hosts
	hosts := "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n"
	if err := os.WriteFile(filepath.Join(etcDir, "hosts"), []byte(hosts), 0644); err != nil {
		return err
	}

	// passwd and group with current user mapped to uid 0
	passwd := fmt.Sprintf("%s:x:0:0::%s:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
		username, homeDir)
	if err := os.WriteFile(filepath.Join(etcDir, "passwd"), []byte(passwd), 0644); err != nil {
		return err
	}

	group := "root:x:0:\nnobody:x:65534:\n"
	if err := os.WriteFile(filepath.Join(etcDir, "group"), []byte(group), 0644); err != nil {
		return err
	}

	// SSL certificates (bind mount from host)
	sslDirs := []string{
		"/etc/ssl/certs",
		"/etc/ssl/cert.pem",
		"/etc/pki/tls/certs",
		"/etc/ca-certificates",
	}
	for _, src := range sslDirs {
		if !pathExists(src) {
			continue
		}
		dst := filepath.Join(rootfs, src)
		os.MkdirAll(filepath.Dir(dst), 0755)
		if isDir(src) {
			os.MkdirAll(dst, 0755)
		} else {
			touchFile(dst)
		}
		unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, "")
		unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
	}

	// Dynamic linker cache — required for finding libraries in non-standard paths
	for _, f := range []string{"/etc/ld.so.cache", "/etc/ld.so.conf"} {
		if pathExists(f) {
			dst := filepath.Join(rootfs, f)
			touchFile(dst)
			unix.Mount(f, dst, "", unix.MS_BIND, "")
			unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
		}
	}
	// Also mount ld.so.conf.d if it exists
	if isDir("/etc/ld.so.conf.d") {
		dst := filepath.Join(rootfs, "etc/ld.so.conf.d")
		os.MkdirAll(dst, 0755)
		unix.Mount("/etc/ld.so.conf.d", dst, "", unix.MS_BIND|unix.MS_REC, "")
		unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
	}

	// /etc/localtime
	if pathExists("/etc/localtime") {
		dst := filepath.Join(etcDir, "localtime")
		touchFile(dst)
		unix.Mount("/etc/localtime", dst, "", unix.MS_BIND, "")
	}

	// /etc/nsswitch.conf — needed for getaddrinfo to work
	nsswitch := "passwd: files\ngroup: files\nhosts: files dns\nnetworks: files\n"
	os.WriteFile(filepath.Join(etcDir, "nsswitch.conf"), []byte(nsswitch), 0644)

	return nil
}

// bindMountRO creates a read-only bind mount.
func bindMountRO(rootfs, src, tgt string) error {
	dst := filepath.Join(rootfs, tgt)
	if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	return unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
}

// bindMountRW creates a read-write bind mount.
func bindMountRW(rootfs, src, tgt string) error {
	dst := filepath.Join(rootfs, tgt)
	return unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, "")
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func touchFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	return f.Close()
}
