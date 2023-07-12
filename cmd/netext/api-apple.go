/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
// void SwiftIntfSet(const char *, const char *, const char*, const char*);
// void UpdateIPNState(int32_t);
// void UpdateBrowserURL(const char *);
// void UpdateEngineState(const char *);
import "C"

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/router"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

var b *backend

//export wgTurnOn
func wgTurnOn() int32 {
	return 0
}

//export miraStartEngine
func miraStartEngine(path *C.char, tunFd int32) int32 {
	if b != nil {
		return 0
	}
	deviceLogger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	errf, err := os.Create(C.GoString(path) + "/output.txt")
	if err != nil {
		deviceLogger.Errorf("Error create output file: %v", err)
	}
	os.Stdout = errf
	os.Stderr = errf

	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		deviceLogger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		deviceLogger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	f := os.NewFile(uintptr(dupTunFd), "/dev/tun")
	tunDev, err := tun.CreateTUNFromFile(f, 0)
	if err != nil {
		deviceLogger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	b, err = newBackend(tunDev, C.GoString(path), deviceLogger.Errorf, setBoth)
	if err != nil {
		deviceLogger.Errorf("Unable to create backend: %v", err)
		return -1
	}
	b.RunLocalAPIServer()
	go runBackend()
	return 0
}

//export wgTurnOff
func wgTurnOff() {

}

func setBoth(r *router.Config, d *dns.OSConfig) error {
	localAddrs := r.LocalAddrs
	routes := r.Routes

	// Convert your Go slices to a form that can be passed to Swift.
	// This will depend on what your Swift function expects.
	// For the sake of this example, let's assume your Swift function takes two arrays of strings.
	var v4AddrsStrs []string
	var v4RoutesStrs []string
	var v6AddrsStrs []string
	var v6RoutesStrs []string

	for _, addr := range localAddrs {
		ipaddr, ipNet, _ := net.ParseCIDR(addr.String())
		if addr.Addr().Is4() {
			v4AddrsStrs = append(v4AddrsStrs, ipaddr.String())
			v4AddrsStrs = append(v4AddrsStrs, net.IP(ipNet.Mask).String())
		} else {
			v6AddrsStrs = append(v6AddrsStrs, ipaddr.String())
			v6AddrsStrs = append(v6AddrsStrs, strconv.Itoa(addr.Bits()))
		}
	}

	for _, route := range routes {
		ipaddr, ipNet, _ := net.ParseCIDR(route.String())
		if route.Addr().Is4() {
			v4RoutesStrs = append(v4RoutesStrs, ipaddr.String())
			v4RoutesStrs = append(v4RoutesStrs, net.IP(ipNet.Mask).String())
		} else {
			v6RoutesStrs = append(v6RoutesStrs, ipaddr.String())
			v6RoutesStrs = append(v6RoutesStrs, strconv.Itoa(route.Bits()))
		}
	}

	// Convert the Go string slices to C arrays.
	// Again, this is a simplification and you'll need to adjust this to match your actual requirements.
	v4AddrsCArray := cstring(strings.Join(v4AddrsStrs, ","))
	v4RoutesCArray := cstring(strings.Join(v4RoutesStrs, ","))
	v6AddrsCArray := cstring(strings.Join(v6AddrsStrs, ","))
	v6RoutesCArray := cstring(strings.Join(v6RoutesStrs, ","))

	C.SwiftIntfSet(v4AddrsCArray, v4RoutesCArray, v6AddrsCArray, v6RoutesCArray)
	return nil
}

type UICommand int32

const (
	OAuth2Event UICommand = iota //0
	ToggleEvent
	BeExitNodeEvent
	ExitAllowLANEvent
	UseTailscaleDNSEvent
	UseTailscaleSubnetsEvent
	AllowIncomingTransactionsEvent
	WebAuthEvent
	SetLoginServerEvent
	LogoutEvent
	ConnectEvent
	RouteAllEvent
	RefreshEngineState
)

//export RunUICommand
func RunUICommand(e int32, input *C.char, addrOut *C.char, addrLen C.size_t) int32 {
	arg := C.GoString(input)
	fmt.Println("RunUICommand", e, arg)

	// Start out NUL-termianted to cover error conditions.
	*addrOut = '\x00'
	switch (UICommand)(e) {
	case ToggleEvent:
		state.Prefs.WantRunning = !state.Prefs.WantRunning
		go b.backend.SetPrefs(state.Prefs)
	case BeExitNodeEvent:
		state.Prefs.SetAdvertiseExitNode(true)
		go b.backend.SetPrefs(state.Prefs)
	case ExitAllowLANEvent:
		state.Prefs.ExitNodeAllowLANAccess = true
		go b.backend.SetPrefs(state.Prefs)
	case UseTailscaleDNSEvent:
		state.Prefs.CorpDNS = true
		go b.backend.SetPrefs(state.Prefs)
	case UseTailscaleSubnetsEvent:
		state.Prefs.RouteAll = true
		go b.backend.SetPrefs(state.Prefs)
	case AllowIncomingTransactionsEvent:
		state.Prefs.ShieldsUp = true
		go b.backend.SetPrefs(state.Prefs)
	case WebAuthEvent:
		out := unsafe.Slice((*byte)(unsafe.Pointer(addrOut)), addrLen)
		n := copy(out, "output")
		out[n] = '\x00'
		if !signingIn {
			go b.backend.StartLoginInteractive()
			signingIn = true
		}
	case SetLoginServerEvent:
		state.Prefs.ControlURL = arg
		b.backend.SetPrefs(state.Prefs)
		// Need to restart to force the login URL to be regenerated
		// with the new control URL. Start from a goroutine to avoid
		// deadlock.
		go func() {
			err := b.backend.Start(ipn.Options{})
			if err != nil {
				//TOTO: log error
			}
		}()
	case LogoutEvent:
		go b.backend.Logout()
	case ConnectEvent:
		state.Prefs.WantRunning = true //TODO: convert from arg
		go b.backend.SetPrefs(state.Prefs)
	case RouteAllEvent:
		state.Prefs.ExitNodeID = tailcfg.StableNodeID(arg)
		go b.backend.SetPrefs(state.Prefs)
		state.updateExitNodes()
	case RefreshEngineState:
		UpdateEngineState(GetEngineState())
	}
	return 0
}

func UpdateNEIPNState(state ipn.State) {
	C.UpdateIPNState(C.int32_t(state))
}

func UpdateBrowserURL(url string) {
	C.UpdateBrowserURL(cstring(url))
}

func UpdateEngineState(engineState string) {
	C.UpdateEngineState(cstring(engineState))
}
