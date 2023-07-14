// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func init() {
	tun.WintunTunnelType = "DigitalGuard"
	guid, err := windows.GUIDFromString("{37217669-42da-4657-a55b-0d995d328255}")
	if err != nil {
		panic(err)
	}
	tun.WintunStaticRequestedGUID = &guid
}

func interfaceName(dev tun.Device) (string, error) {
	guid, err := winipcfg.LUID(dev.(*tun.NativeTun).LUID()).GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}
