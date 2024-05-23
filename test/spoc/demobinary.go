/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
import "C"

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const LogPrefixEnvVar = "LOGPREFIX"

// Demo binary to exercise various capabilities that may be restricted by seccomp/apparmor.
func main() {
	log.SetPrefix(fmt.Sprintf("%s[pid:%d] ", os.Getenv(LogPrefixEnvVar), os.Getpid()))
	log.SetFlags(log.Lshortfile)
	log.Println("⏩", os.Args)

	capSysAdmin := flag.Bool("cap-sys-admin", false, "exercise CAP_SYS_ADMIN")
	fileWrite := flag.String("file-write", "", "write file (e.g. /dev/null)")
	fileRead := flag.String("file-read", "", "read file (e.g. /dev/null)")
	fileSymlink := flag.String("file-symlink", "", "Create symlink using the following syntax: OLD:NEW")
	netTCP := flag.Bool("net-tcp", false, "spawn a tcp server")
	netUDP := flag.Bool("net-udp", false, "spawn a udp server")
	netIcmp := flag.Bool("net-icmp", false, "open an icmp socket, exercise NET_RAW capability.")
	library := flag.String("load-library", "", "load a shared library")
	sleep := flag.Int("sleep", 0, "sleep N seconds before exiting.")
	crash := flag.Bool("crash", false, "crash instead of exiting.")

	flag.Parse()

	subprocess := flag.Args()

	if *capSysAdmin {
		// Modifying niceness of another process requires CAP_SYS_ADMIN.
		err := os.WriteFile("/proc/1/autogroup", []byte("0"), 0)
		if err != nil {
			log.Fatal("❌ Error exercising CAP_SYS_ADMIN:", err)
		}
		log.Println("✅ CAP_SYS_ADMIN is available.")
	}
	if *fileWrite != "" {
		const fileMode = 0o666
		err := os.WriteFile(*fileWrite, []byte{}, fileMode)
		if err != nil {
			log.Fatal("❌ Error creating file:", err)
		}
		log.Println("✅ File write successful:", *fileWrite)
		// make file writable for other users so that sudo/non-sudo testing works.
		err = os.Chmod(*fileWrite, fileMode)
		if err != nil {
			log.Fatal("❌ Error setting file permissions:", err)
		}
	}
	if *fileSymlink != "" {
		oldname, newname, found := strings.Cut(*fileSymlink, ":")
		if !found {
			log.Fatal("❌ Symlink syntax: OLD:NEW")
		}
		err := os.Symlink(oldname, newname)
		if err != nil {
			log.Fatal("❌ Error creating symlink:", err)
		}
		log.Println("✅ Symlink created:", newname, "->", oldname)
	}
	if *fileRead != "" {
		_, err := os.ReadFile(*fileRead)
		if err != nil {
			log.Fatal("❌ Error reading file:", err)
		}
		log.Println("✅ File read successful:", *fileRead)
	}
	if *netTCP {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			log.Fatal("❌ Error starting TCP server:", err)
		}
		log.Println("✅ TCP server spawned:", listener.Addr())
		defer listener.Close()
	}
	if *netUDP {
		server, err := net.ListenPacket("udp", ":0")
		if err != nil {
			//nolint:gocritic  // gocritic is terminally confused here.
			log.Fatal("❌ Error starting UDP server:", err)
		}
		log.Println("✅ UDP server spawned:", server.LocalAddr())
		defer server.Close()
	}
	if *netIcmp {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err != nil {
			log.Fatal("❌ Error opening ICMP socket:", err)
		}
		log.Println("✅ ICMP socket opened: fd", fd)
		defer syscall.Close(fd)
	}
	if len(subprocess) > 0 {
		cmd := exec.Command(subprocess[0], subprocess[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), "LOGPREFIX=\t"+os.Getenv(LogPrefixEnvVar))
		err := cmd.Run()
		if err != nil {
			log.Fatal("❌ Error running subprocess:", err)
		}
		log.Println("✅ Subprocess ran successfully:", subprocess)
	}
	if *library != "" {
		if handle := C.dlopen(C.CString(*library), C.RTLD_NOW); handle == nil {
			log.Fatal("❌ Error loading library: ", C.GoString(C.dlerror()))
		}
		log.Println("✅ Library loaded successfully:", *library)
	}
	if *sleep > 0 {
		log.Println("⏳ Sleeping for", *sleep, "seconds...")
		time.Sleep(time.Duration(*sleep) * time.Second)
	}
	if *crash {
		log.Println("🫡  Terminating with SIGKILL...")
		err := syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		if err != nil {
			log.Fatal("❌ Error sending SIGKILL:", err)
		}
	}
	log.Println("⭐️ Success.")
}
