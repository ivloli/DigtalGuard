// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

type ExitStatus uint8

const (
	// No exit node selected.
	ExitNone ExitStatus = iota
	// Exit node selected and exists, but is offline or missing.
	ExitOffline
	// Exit node selected and online.
	ExitOnline
)

type Peer struct {
	Label  string
	Online bool
	ID     tailcfg.StableNodeID
}

type BackendState struct {
	Prefs        *ipn.Prefs
	State        ipn.State
	NetworkMap   *netmap.NetworkMap
	LostInternet bool
	// Exits are the peers that can act as exit node.
	Exits []Peer
	// ExitState describes the state of our exit node.
	ExitStatus ExitStatus
	// Exit is our current exit node, if any.
	Exit        Peer
	BrowseToURL string
}

func (s *BackendState) updateExitNodes() {
	s.ExitStatus = ExitNone
	var exitID tailcfg.StableNodeID
	if p := s.Prefs; p != nil {
		exitID = p.ExitNodeID
		if exitID != "" {
			s.ExitStatus = ExitOffline
		}
	}
	hasMyExit := exitID == ""
	s.Exits = nil
	var peers []*tailcfg.Node
	if s.NetworkMap != nil {
		peers = s.NetworkMap.Peers
	}
	for _, p := range peers {
		canRoute := false
		for _, r := range p.AllowedIPs {
			if r == netip.MustParsePrefix("0.0.0.0/0") || r == netip.MustParsePrefix("::/0") {
				canRoute = true
				break
			}
		}
		myExit := p.StableID == exitID
		hasMyExit = hasMyExit || myExit
		exit := Peer{
			Label:  p.DisplayName(true),
			Online: canRoute,
			ID:     p.StableID,
		}
		if myExit {
			s.Exit = exit
			if canRoute {
				s.ExitStatus = ExitOnline
			}
		}
		if canRoute || myExit {
			s.Exits = append(s.Exits, exit)
		}
	}
	sort.Slice(s.Exits, func(i, j int) bool {
		return s.Exits[i].Label < s.Exits[j].Label
	})
	if !hasMyExit {
		// Insert node missing from netmap.
		s.Exit = Peer{Label: "Unknown device", ID: exitID}
		s.Exits = append([]Peer{s.Exit}, s.Exits...)
	}
}

var (
	state     BackendState
	signingIn bool
)

func runBackend() error {

	notifications := make(chan ipn.Notify, 1)
	startErr := make(chan error)
	// Start from a goroutine to avoid deadlock when Start
	// calls the callback.
	go func() {
		startErr <- b.Start(func(n ipn.Notify) {
			notifications <- n
		})
	}()
	for {
		select {
		case err := <-startErr:
			if err != nil {
				return err
			}
		case n := <-notifications:
			if p := n.Prefs; p != nil && n.Prefs.Valid() {
				first := state.Prefs == nil
				state.Prefs = p.AsStruct()
				state.updateExitNodes()
				if first {
					hostname, _ := os.Hostname() //TODO: get host name by NE API
					state.Prefs.Hostname = hostname
					go b.backend.SetPrefs(state.Prefs)
				}
			}
			if s := n.State; s != nil {
				oldState := state.State
				state.State = *s
				UpdateNEIPNState(state.State)

				// Stop VPN if we logged out.
				if oldState > ipn.Stopped && state.State <= ipn.Stopped {
					// TODO, notify app to stop VPN, maybe NE can just all stopTunnel directly?
				}
			}
			if u := n.BrowseToURL; u != nil {
				signingIn = false
				state.BrowseToURL = *u
				UpdateBrowserURL(state.BrowseToURL)
			}
			if m := n.NetMap; m != nil {
				state.NetworkMap = m
				state.updateExitNodes()
				UpdateEngineState(GetEngineState())
			}
		}
	}
}

func GetEngineState() string {
	type Node struct {
		NodeName string
		IP       string
	}
	type EngineState struct {
		UserName  string
		NodeName  string
		IP        string
		Peers     []*Node
		ExitNodes []Peer
		ShieldsUp bool
		CorpDNS   bool
		RouteAll  bool
	}
	m := state.NetworkMap
	netMap := EngineState{
		UserName:  m.UserProfiles[m.User].DisplayName,
		NodeName:  m.SelfNode.Hostinfo.Hostname(),
		IP:        m.Addresses[0].Addr().String(),
		Peers:     make([]*Node, 0, len(m.Peers)),
		ExitNodes: state.Exits,
		ShieldsUp: state.Prefs.ShieldsUp,
		CorpDNS:   state.Prefs.CorpDNS,
		RouteAll:  state.Prefs.RouteAll,
	}
	for _, peer := range state.NetworkMap.Peers {
		netMap.Peers = append(netMap.Peers, &Node{
			NodeName: peer.Hostinfo.Hostname(),
			IP:       peer.Addresses[0].Addr().String(),
		})
	}
	jstring, _ := json.Marshal(netMap)
	fmt.Println("---------------------------")
	fmt.Println(string(jstring))
	fmt.Println("---------------------------")
	return string(jstring)
}

func main() {}
