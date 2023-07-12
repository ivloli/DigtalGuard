// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/ipn/store"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/smallzstd"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

type backend struct {
	engine     wgengine.Engine
	backend    *ipnlocal.LocalBackend
	settings   settingsFunc
	lastCfg    *router.Config
	lastDNSCfg *dns.OSConfig

	logIDPublic string
	logger      *logtail.Logger

	// avoidEmptyDNS controls whether to use fallback nameservers
	// when no nameservers are provided by Tailscale.
	avoidEmptyDNS bool
	lah           *localapi.Handler
}

type settingsFunc func(*router.Config, *dns.OSConfig) error

const defaultMTU = 1280 // minimalMTU from wgengine/userspace.go

const (
	logPrefKey               = "privatelogid"
	loginMethodPrefKey       = "loginmethod"
	customLoginServerPrefKey = "customloginserver"
)

const (
	loginMethodGoogle = "google"
	loginMethodWeb    = "web"
)

var tstunNew = tstun.New

// googleDNSServers are used on ChromeOS, where an empty VpnBuilder DNS setting results
// in erasing the platform DNS servers. The developer docs say this is not supposed to happen,
// but nonetheless it does.
var googleDNSServers = []netip.Addr{
	netip.MustParseAddr("223.5.5.5"),
	netip.MustParseAddr("223.6.6.6"),
	netip.MustParseAddr("2400:3200::1"),
	netip.MustParseAddr("2400:3200:baba::1"),
}

func newBackend(dataDir string, logf logger.Logf, settings settingsFunc) (*backend, error) {

	sys := new(tsd.System)
	netMon, err := netmon.New(func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		return nil, fmt.Errorf("netmon.New: %w", err)
	}
	sys.Set(netMon)
	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	sys.Set(dialer)
	name := "ShuZiWeiShi0"
	conf := wgengine.Config{
		ListenPort:   0,
		NetMon:       sys.NetMon.Get(),
		Dialer:       sys.Dialer.Get(),
		SetSubsystem: sys.Set,
	}
	dev, devName, err := tstunNew(logf, name)
	if err != nil {
		tstun.Diagnose(logf, name, err)
		return nil, fmt.Errorf("tstun.New(%q): %w", name, err)
	}
	conf.Tun = dev

	r, err := router.New(logf, dev, sys.NetMon.Get())
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("creating router: %w", err)
	}

	d, err := dns.NewOSConfigurator(logf, devName)
	if err != nil {
		dev.Close()
		r.Close()
		return nil, fmt.Errorf("dns.NewOSConfigurator: %w", err)
	}
	conf.DNS = d
	conf.Router = r
	sys.Set(conf.Router)
	engine, err := wgengine.NewUserspaceEngine(logf, conf)
	store, err := store.New(logf, filepath.Join(dataDir, "ShuZiWeiShi.state"))
	if err != nil {
		return nil, fmt.Errorf("store.New: %w", err)
	}
	sys.Set(store)

	//logf := logger.RusagePrefixLog(log.Printf)
	b := &backend{
		settings: settings,
	}
	var logID logid.PrivateID
	logID.UnmarshalText([]byte("dead0000dead0000dead0000dead0000dead0000dead0000dead0000dead0000"))

	b.SetupLogs(dataDir, logID)
	if err != nil {
		return nil, fmt.Errorf("runBackend: NewUserspaceEngine: %v", err)
	}
	sys.Set(engine)
	b.logIDPublic = logID.Public().String()
	ns, err := netstack.Create(logf, sys.Tun.Get(), engine, sys.MagicSock.Get(), dialer, sys.DNSManager.Get())
	if err != nil {
		return nil, fmt.Errorf("netstack.Create: %w", err)
	}
	ns.ProcessLocalIPs = false // let Android kernel handle it; VpnBuilder sets this up
	ns.ProcessSubnets = true   // for Android-being-an-exit-node support
	sys.NetstackRouter.Set(true)
	lb, err := ipnlocal.NewLocalBackend(logf, logID.Public(), sys, 0)
	if err != nil {
		engine.Close()
		return nil, fmt.Errorf("runBackend: NewLocalBackend: %v", err)
	}
	if err := ns.Start(lb); err != nil {
		return nil, fmt.Errorf("startNetstack: %w", err)
	}
	if b.logger != nil {
		lb.SetLogFlusher(b.logger.StartFlush)
	}
	b.engine = engine
	b.backend = lb
	lah := localapi.NewHandler(lb, logf, nil, logID.Public())
	lah.PermitRead, lah.PermitWrite = true, true
	lah.PermitCert = true
	b.lah = lah

	return b, nil
}

func (b *backend) Start(notify func(n ipn.Notify)) error {
	b.backend.SetNotifyCallback(notify)

	newPrefs := ipn.NewPrefs()
	newPrefs.ControlURL = globalCfg.ControlUrl
	newPrefs.CorpDNS = false
	newPrefs.RouteAll = true
	newPrefs.AdvertiseRoutes = []netip.Prefix{
		netip.MustParsePrefix("172.16.21.252/32"),
	}
	//newPrefs.WantRunning = true
	return b.backend.Start(ipn.Options{
		//AuthKey: "tskey-auth-kRHXEb2CNTRL-CgdxZTYTmue6o8seXzKjueUMwkkCL4hd",
		AuthKey: globalCfg.AuthKey,
		//LegacyMigrationPrefs: newPrefs,
	})
}

func (b *backend) setCfg(rcfg *router.Config, dcfg *dns.OSConfig) error {
	return b.settings(rcfg, dcfg)
}

// CloseVPN closes any active TUN devices.
func (b *backend) CloseTUNs() {
	b.lastCfg = nil
}

// SetupLogs sets up remote logging.
func (b *backend) SetupLogs(logDir string, logID logid.PrivateID) {
	logf := logger.RusagePrefixLog(log.Printf)
	netMon, err := netmon.New(func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		log.Printf("netmon.New: %w", err)
	}
	transport := logpolicy.NewLogtailTransport(logtail.DefaultHost, netMon)

	logcfg := logtail.Config{
		Collection:          logtail.CollectionNode,
		PrivateID:           logID,
		Stderr:              log.Writer(),
		MetricsDelta:        clientmetric.EncodeLogTailMetricsDelta,
		IncludeProcID:       true,
		IncludeProcSequence: true,
		NewZstdEncoder: func() logtail.Encoder {
			return must.Get(smallzstd.NewEncoder(nil))
		},
		HTTPC: &http.Client{Transport: transport},
	}
	logcfg.FlushDelayFn = func() time.Duration { return 2 * time.Minute }

	/* this causes a LOT of RAW-STDERR in filch'ed files ipn.log..log1.txt
	filchOpts := filch.Options{
		ReplaceStderr: true,
	}

		var filchErr error
		if logDir != "" {
			logPath := filepath.Join(logDir, "ipn.log.")
			logcfg.Buffer, filchErr = filch.New(logPath, filchOpts)
		}
	*/

	b.logger = logtail.NewLogger(logcfg, logf)

	log.SetFlags(0)
	log.SetOutput(b.logger)

	log.Printf("goSetupLogs: success")

	if logDir == "" {
		log.Printf("SetupLogs: no logDir, storing logs in memory")
	}
	/*
		if filchErr != nil {
			log.Printf("SetupLogs: filch setup failed: %v", filchErr)
		}
	*/
}

func (b *backend) getPlatformDNSConfig() string {
	var baseConfig string
	// rewrite with Swift code call
	return baseConfig
}

func (b *backend) getDNSBaseConfig() (ret dns.OSConfig, _ error) {
	defer func() {
		// If we couldn't find any base nameservers, ultimately fall back to
		// Google's. Normally Tailscale doesn't ever pick a default nameserver
		// for users but in this case Android's APIs for reading the underlying
		// DNS config are lacking, and almost all Android phones use Google
		// services anyway, so it's a reasonable default: it's an ecosystem the
		// user has selected by having an Android device.
		if len(ret.Nameservers) == 0 {
			log.Printf("getDNSBaseConfig: none found; falling back to Google public DNS")
			ret.Nameservers = append(ret.Nameservers, googleDNSServers...)
		}
	}()
	baseConfig := b.getPlatformDNSConfig()
	lines := strings.Split(baseConfig, "\n")
	if len(lines) == 0 {
		return dns.OSConfig{}, nil
	}

	config := dns.OSConfig{}
	addrs := strings.Trim(lines[0], " \n")
	for _, addr := range strings.Split(addrs, " ") {
		ip, err := netip.ParseAddr(addr)
		if err == nil {
			config.Nameservers = append(config.Nameservers, ip)
		}
	}

	if len(lines) > 1 {
		for _, s := range strings.Split(strings.Trim(lines[1], " \n"), " ") {
			domain, err := dnsname.ToFQDN(s)
			if err != nil {
				log.Printf("getDNSBaseConfig: unable to parse %q: %v", s, err)
				continue
			}
			config.SearchDomains = append(config.SearchDomains, domain)
		}
	}

	return config, nil
}

func (b *backend) RunLocalAPIServer() {
	http.HandleFunc("/localapi/", func(w http.ResponseWriter, r *http.Request) {
		// Assuming lah is your handler
		b.lah.ServeHTTP(w, r)
	})

	go http.ListenAndServe("127.0.0.1:60600", nil)
}

func (b *backend) RunLocalCustomServer() {
	mux := http.NewServeMux()

	// 注册路由处理函数
	mux.HandleFunc("/getIPs", b.getIPsHandler)
	mux.HandleFunc("/disconnect", b.disconnect)
	mux.HandleFunc("/login", b.login)
	mux.HandleFunc("/logout", b.logout)
	mux.HandleFunc("/getState", b.getState)
	mux.HandleFunc("/reconnect", b.reconnect)

	// 创建 HTTP 服务端
	server := &http.Server{
		Addr:    ":28090",
		Handler: mux,
	}

	// 启动服务
	go server.ListenAndServe()
}

type CustomResp struct {
	Data map[string]any `json:"data"`
	Code int64          `json:"code"`
	Msg  string         `json:"msg"`
}

func (b *backend) getIPsHandler(w http.ResponseWriter, r *http.Request) {
	ips := []string{}
	if b != nil && b.backend != nil {
		st := b.backend.StatusWithoutPeers()
		for _, v := range st.TailscaleIPs {
			if v.Is4() {
				ips = append(ips, v.String())
			}
		}
	}

	// 序列化 JSON 响应
	newResp := &CustomResp{
		Data: map[string]any{
			"ips": ips,
		},
		Code: 0,
		Msg:  "ok",
	}
	response, _ := json.Marshal(newResp)

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	if len(ips) > 0 {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
	// 发送 JSON 响应
	w.Write(response)
}

func (b *backend) logout(w http.ResponseWriter, r *http.Request) {
	var err error
	if b.backend.State() == ipn.Running || b.backend.State() == ipn.Starting {
	} else {
		err = errors.New("node is not Running")
	}
	if err == nil {

		err = b.backend.LogoutSync(context.Background())
		signingIn = false
		state.Prefs = nil
	}
	newResp := &CustomResp{
		Data: map[string]any{},
		Code: 0,
		Msg:  "ok",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err != nil {
		newResp.Code = -1
		newResp.Msg = "Logout failed: " + err.Error()
	}
	response, _ := json.Marshal(newResp)
	w.Write(response)
}
func (b *backend) disconnect(w http.ResponseWriter, r *http.Request) {
	var err error
	if b.backend.State() == ipn.Running || b.backend.State() == ipn.Starting {
	} else {
		err = errors.New("node is not Running")
	}
	if err == nil {
		_, err = b.backend.EditPrefs(&ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				WantRunning: false,
			},
			WantRunningSet: true,
		})
		signingIn = false
		state.Prefs = nil
	}
	newResp := &CustomResp{
		Data: map[string]any{},
		Code: 0,
		Msg:  "ok",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err != nil {
		newResp.Code = -1
		newResp.Msg = "Logout failed: " + err.Error()
	}
	response, _ := json.Marshal(newResp)
	w.Write(response)
}

func (b *backend) login(w http.ResponseWriter, r *http.Request) {
	var err error
	newPrefs := ipn.NewPrefs()
	hostname, _ := os.Hostname()

	newPrefs.ControlURL = globalCfg.ControlUrl
	newPrefs.Hostname = hostname + "_ShuZiWeiShi"
	newPrefs.CorpDNS = false
	newPrefs.RouteAll = true
	newPrefs.AdvertiseRoutes = []netip.Prefix{
		netip.MustParsePrefix("172.16.21.252/32"),
	}
	newPrefs.WantRunning = true
	if err == nil {
		/*
			err = b.backend.Start(ipn.Options{
				//AuthKey: "tskey-auth-kRHXEb2CNTRL-CgdxZTYTmue6o8seXzKjueUMwkkCL4hd",
				AuthKey:     globalCfg.AuthKey,
				UpdatePrefs: newPrefs,
			})
		*/

		b.backend.EditPrefs(&ipn.MaskedPrefs{
			Prefs:              *newPrefs,
			ControlURLSet:      true,
			CorpDNSSet:         true,
			RouteAllSet:        true,
			AdvertiseRoutesSet: true,
			WantRunningSet:     true,
		})
		logf("xxxx")
		b.backend.StartLoginInteractive()
		logf("yyyyyy")
		signingIn = true
	}
	newResp := &CustomResp{
		Data: map[string]any{},
		Code: 0,
		Msg:  "ok",
	}
	if err != nil {
		newResp.Code = -1
		newResp.Msg = "Login failed: " + err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response, _ := json.Marshal(newResp)
	w.Write(response)
}

func (b *backend) reconnect(w http.ResponseWriter, r *http.Request) {

	b.backend.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			WantRunning: true,
		},
		WantRunningSet: true,
	})
	logf("zzzzz")
	newResp := &CustomResp{
		Data: map[string]any{},
		Code: 0,
		Msg:  "ok",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response, _ := json.Marshal(newResp)
	w.Write(response)
}

func (b *backend) getState(w http.ResponseWriter, r *http.Request) {
	newResp := &CustomResp{
		Data: map[string]any{
			"state": b.backend.State().String(),
		},
		Code: 0,
		Msg:  "ok",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response, _ := json.Marshal(newResp)
	w.Write(response)
}
