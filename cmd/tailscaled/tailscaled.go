// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tailscaled program is the Tailscale client daemon. It's configured
// and controlled via the tailscale CLI program.
//
// It primarily supports Linux, though other systems will likely be
// supported in the future.
package main // import "tailscale.com/cmd/tailscaled"

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"gopkg.in/yaml.v2"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/dns"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/net/tstun"
	"tailscale.com/paths"
	"tailscale.com/smallzstd"
	"tailscale.com/syncs"
	"tailscale.com/tsd"
	"tailscale.com/tsweb/varz"
	"tailscale.com/types/flagtype"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/preftype"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/multierr"
	"tailscale.com/util/osshare"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

// defaultTunName returns the default tun device name for the platform.
func defaultTunName() string {
	switch runtime.GOOS {
	case "openbsd":
		return "tun"
	case "windows":
		return "digitalGuard001"
	case "darwin":
		// "utun" is recognized by wireguard-go/tun/tun_darwin.go
		// as a magic value that uses/creates any free number.
		return "utun"
	case "linux":
		switch distro.Get() {
		case distro.Synology:
			// Try TUN, but fall back to userspace networking if needed.
			// See https://github.com/tailscale/tailscale-synology/issues/35
			return "tailscale0,userspace-networking"
		case distro.Gokrazy:
			// Gokrazy doesn't yet work in tun mode because the whole
			// Gokrazy thing is no C code, and Tailscale currently
			// depends on the iptables binary for Linux's
			// wgengine/router.
			// But on Gokrazy there's no legacy iptables, so we could use netlink
			// to program nft-iptables directly. It just isn't done yet;
			// see https://github.com/tailscale/tailscale/issues/391
			//
			// But Gokrazy does have the tun module built-in, so users
			// can still run --tun=tailscale0 if they wish, if they
			// arrange for iptables to be present or run in "tailscale
			// up --netfilter-mode=off" mode, perhaps. Untested.
			return "userspace-networking"
		}

	}
	return "digitalGuard01"
}

// defaultPort returns the default UDP port to listen on for disco+wireguard.
// By default it returns 0, to pick one randomly from the kernel.
// If the environment variable PORT is set, that's used instead.
// The PORT environment variable is chosen to match what the Linux systemd
// unit uses, to make documentation more consistent.
func defaultPort() uint16 {
	if s := envknob.String("PORT"); s != "" {
		if p, err := strconv.ParseUint(s, 10, 16); err == nil {
			return uint16(p)
		}
	}
	if envknob.GOOS() == "windows" {
		return 41652
	}
	return 0
}

var args struct {
	// tunname is a /dev/net/tun tunnel name ("tailscale0"), the
	// string "userspace-networking", "tap:TAPNAME[:BRIDGENAME]"
	// or comma-separated list thereof.
	tunname string

	cleanup        bool
	debug          string
	port           uint16
	statepath      string
	statedir       string
	socketpath     string
	birdSocketPath string
	verbose        int
	socksAddr      string // listen address for SOCKS5 server
	httpProxyAddr  string // listen address for HTTP proxy server
	disableLogs    bool
}

var (
	installSystemDaemon   func([]string) error                      // non-nil on some platforms
	uninstallSystemDaemon func([]string) error                      // non-nil on some platforms
	createBIRDClient      func(string) (wgengine.BIRDClient, error) // non-nil on some platforms
)

var subCommands = map[string]*func([]string) error{
	"install-system-daemon":   &installSystemDaemon,
	"uninstall-system-daemon": &uninstallSystemDaemon,
	"debug":                   &debugModeFunc,
	"be-child":                &beChildFunc,
}

var beCLI func() // non-nil if CLI is linked in

func GetAppDirectory() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))

	return path[:index]
}

type Config struct {
	ControlUrl       string   `yaml:"controlUrl"`
	AuthKey          string   `yaml:"authKey"`
	DataDir          string   `yaml:"dataDir"`
	HostSuffix       string   `yaml:"hostSuffix"`
	AutoConnect      bool     `yaml:"autoConnect"`
	AdvertiseRoutes  []string `yaml:"advertiseRoutes"`
	ProcessExistence string   `yaml:"processExistence"`
}

func readConfig(filename string) (*Config, error) {
	// 读取文件内容
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// 解析 YAML
	config := &Config{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

var globalConfig *Config

type loginErrWarpper struct {
	Code int
	Err  error
}

var loginErr loginErrWarpper = loginErrWarpper{
	Code: 100,
	Err:  errors.New("Not login yet"),
}

func main() {
	envknob.PanicIfAnyEnvCheckedInInit()
	envknob.ApplyDiskConfig()

	printVersion := false
	shadowArg := ""
	flag.IntVar(&args.verbose, "verbose", 0, "log verbosity level; 0 is default, 1 or higher are increasingly verbose")
	flag.BoolVar(&args.cleanup, "cleanup", false, "clean up system state and exit")
	flag.StringVar(&args.debug, "debug", "", "listen address ([ip]:port) of optional debug server")
	flag.StringVar(&args.socksAddr, "socks5-server", "", `optional [ip]:port to run a SOCK5 server (e.g. "localhost:1080")`)
	flag.StringVar(&args.httpProxyAddr, "outbound-http-proxy-listen", "", `optional [ip]:port to run an outbound HTTP proxy (e.g. "localhost:8080")`)
	flag.StringVar(&args.tunname, "tun", defaultTunName(), `tunnel interface name; use "userspace-networking" (beta) to not use TUN`)
	flag.Var(flagtype.PortValue(&args.port, defaultPort()), "port", "UDP port to listen on for WireGuard and peer-to-peer traffic; 0 means automatically select")
	flag.StringVar(&args.statepath, "state", "", "absolute path of state file; use 'kube:<secret-name>' to use Kubernetes secrets or 'arn:aws:ssm:...' to store in AWS SSM; use 'mem:' to not store state and register as an ephemeral node. If empty and --statedir is provided, the default is <statedir>/tailscaled.state. Default: "+paths.DefaultTailscaledStateFile())
	flag.StringVar(&args.statedir, "statedir", "", "path to directory for storage of config state, TLS certs, temporary incoming Taildrop files, etc. If empty, it's derived from --state when possible.")
	flag.StringVar(&args.socketpath, "socket", paths.DefaultTailscaledSocket(), "path of the service unix socket")
	flag.StringVar(&args.birdSocketPath, "bird-socket", "", "path of the bird unix socket")
	flag.BoolVar(&printVersion, "version", false, "print version information and exit")
	flag.BoolVar(&args.disableLogs, "no-logs-no-support", false, "disable log uploads; this also disables any technical support")
	flag.StringVar(&shadowArg, "shadow-arg", "my precious", "just a shadow")
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "tailscale" && beCLI != nil {
		beCLI()
		return
	}
	if len(os.Args) < 2 {
		fmt.Println("cannot run directly")
		return
	}
	config, err := readConfig(filepath.Join(GetAppDirectory(), "config.yaml"))
	globalConfig = &Config{
		ControlUrl: "https://47.93.215.62:8888",
		AuthKey:    "5b4958754e0648075c2ce386365e26a99d19b490dbcbb846",
		DataDir:    `C:\ProgramData\DigitalGuard`,
	}
	if err != nil {
		log.Printf("empty config file, use default")
	} else {
		if config.ControlUrl != "" {
			globalConfig.ControlUrl = config.ControlUrl
		}
		if config.AuthKey != "" {
			globalConfig.AuthKey = config.AuthKey
		}
		if config.DataDir != "" {
			globalConfig.DataDir = config.DataDir
		}
		if config.HostSuffix != "" {
			globalConfig.HostSuffix = config.HostSuffix
		}
		if len(config.AdvertiseRoutes) > 0 {
			globalConfig.AdvertiseRoutes = config.AdvertiseRoutes
		}
		globalConfig.AutoConnect = config.AutoConnect
		globalConfig.ProcessExistence = config.ProcessExistence
	}
	if len(os.Args) > 1 {
		sub := os.Args[1]
		if fp, ok := subCommands[sub]; ok {
			if *fp == nil {
				log.SetFlags(0)
				log.Fatalf("%s not available on %v", sub, runtime.GOOS)
			}
			if err := (*fp)(os.Args[2:]); err != nil {
				log.SetFlags(0)
				log.Fatal(err)
			}
			return
		}
	}

	flag.Parse()
	if flag.NArg() > 0 {
		// Windows subprocess is spawned with /subprocess, so we need to avoid this check there.
		if runtime.GOOS != "windows" || (flag.Arg(0) != "/subproc" && flag.Arg(0) != "/firewall") {
			log.Fatalf("digital guard does not take non-flag arguments: %q", flag.Args())
		}
	}
	log.Printf("shadow is %v", shadowArg)
	if printVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	if runtime.GOOS == "darwin" && os.Getuid() != 0 && !strings.Contains(args.tunname, "userspace-networking") && !args.cleanup {
		log.SetFlags(0)
		log.Fatalf("tailscaled requires root; use sudo tailscaled (or use --tun=userspace-networking)")
	}

	/*
		if args.socketpath == "" && runtime.GOOS != "windows" {
			log.SetFlags(0)
			log.Fatalf("--socket is required")
		}
	*/

	if args.birdSocketPath != "" && createBIRDClient == nil {
		log.SetFlags(0)
		log.Fatalf("--bird-socket is not supported on %s", runtime.GOOS)
	}

	// Only apply a default statepath when neither have been provided, so that a
	// user may specify only --statedir if they wish.
	if args.statepath == "" && args.statedir == "" {
		//args.statepath = paths.DefaultTailscaledStateFile()
		if globalConfig.DataDir != "" {
			args.statedir = globalConfig.DataDir
		} else {
			args.statedir = GetAppDirectory()
		}
		args.statepath = filepath.Join(args.statedir, "DigitalGuard.state")
	}

	args.disableLogs = true
	if args.disableLogs {
		envknob.SetNoLogsNoSupport()
	}

	if beWindowsSubprocess() {
		return
	}

	err = run()

	// Remove file sharing from Windows shell (noop in non-windows)
	osshare.SetFileSharingEnabled(false, logger.Discard)

	if err != nil {
		log.Fatal(err)
	}
}

func trySynologyMigration(p string) error {
	if runtime.GOOS != "linux" || distro.Get() != distro.Synology {
		return nil
	}

	fi, err := os.Stat(p)
	if err == nil && fi.Size() > 0 || !os.IsNotExist(err) {
		return err
	}
	// File is empty or doesn't exist, try reading from the old path.

	const oldPath = "/var/packages/Tailscale/etc/tailscaled.state"
	if _, err := os.Stat(oldPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if err := os.Chown(oldPath, os.Getuid(), os.Getgid()); err != nil {
		return err
	}
	if err := os.Rename(oldPath, p); err != nil {
		return err
	}
	return nil
}

func statePathOrDefault() string {
	if args.statepath != "" {
		return args.statepath
	}
	if args.statedir != "" {
		return filepath.Join(args.statedir, "tailscaled.state")
	}
	return ""
}

// serverOptions is the configuration of the Tailscale node agent.
type serverOptions struct {
	// VarRoot is the Tailscale daemon's private writable
	// directory (usually "/var/lib/tailscale" on Linux) that
	// contains the "tailscaled.state" file, the "certs" directory
	// for TLS certs, and the "files" directory for incoming
	// Taildrop files before they're moved to a user directory.
	// If empty, Taildrop and TLS certs don't function.
	VarRoot string

	// LoginFlags specifies the LoginFlags to pass to the client.
	LoginFlags controlclient.LoginFlags
}

func ipnServerOpts() (o serverOptions) {
	goos := envknob.GOOS()

	o.VarRoot = args.statedir

	// If an absolute --state is provided but not --statedir, try to derive
	// a state directory.
	if o.VarRoot == "" && filepath.IsAbs(args.statepath) {
		if dir := filepath.Dir(args.statepath); strings.EqualFold(filepath.Base(dir), "tailscale") {
			o.VarRoot = dir
		}
	}
	if strings.HasPrefix(statePathOrDefault(), "mem:") {
		// Register as an ephemeral node.
		o.LoginFlags = controlclient.LoginEphemeral
	}

	switch goos {
	case "js":
		// The js/wasm client has no state storage so for now
		// treat all interactive logins as ephemeral.
		// TODO(bradfitz): if we start using browser LocalStorage
		// or something, then rethink this.
		o.LoginFlags = controlclient.LoginEphemeral
	case "windows":
		// Not those.
	}
	return o
}

var logPol *logpolicy.Policy
var debugMux *http.ServeMux

func run() error {
	var logf logger.Logf = log.Printf

	sys := new(tsd.System)

	netMon, err := netmon.New(func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		return fmt.Errorf("netmon.New: %w", err)
	}
	sys.Set(netMon)

	pol := logpolicy.New(logtail.CollectionNode, netMon)
	pol.SetVerbosityLevel(args.verbose)
	logPol = pol
	defer func() {
		// Finish uploading logs after closing everything else.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		pol.Shutdown(ctx)
	}()

	if err := envknob.ApplyDiskConfigError(); err != nil {
		log.Printf("Error reading environment config: %v", err)
	}

	if isWindowsService() {
		// Run the IPN server from the Windows service manager.
		log.Printf("Running service...")
		if err := runWindowsService(pol); err != nil {
			log.Printf("runservice: %v", err)
		}
		log.Printf("Service ended.")
		return nil
	}

	if envknob.Bool("TS_DEBUG_MEMORY") {
		logf = logger.RusagePrefixLog(logf)
	}
	logf = logger.RateLimitedFn(logf, 5*time.Second, 5, 100)

	if args.cleanup {
		if envknob.Bool("TS_PLEASE_PANIC") {
			panic("TS_PLEASE_PANIC asked us to panic")
		}
		dns.Cleanup(logf, args.tunname)
		router.Cleanup(logf, args.tunname)
		return nil
	}

	if args.statepath == "" && args.statedir == "" {
		log.Fatalf("--statedir (or at least --state) is required")
	}
	if err := trySynologyMigration(statePathOrDefault()); err != nil {
		log.Printf("error in synology migration: %v", err)
	}

	if args.debug != "" {
		debugMux = newDebugMux()
	}

	return startIPNServer(context.Background(), logf, pol.PublicID, sys)
}

type MyLocalBackend struct {
	backend *ipnlocal.LocalBackend
	logf    logger.Logf
}

func startIPNServer(ctx context.Context, logf logger.Logf, logID logid.PublicID, sys *tsd.System) error {
	//ln, err := safesocket.Listen(args.socketpath)
	ln, err := net.Listen("tcp", "0.0.0.0:60600")
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Exit gracefully by cancelling the ipnserver context in most common cases:
	// interrupted from the TTY or killed by a service manager.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	// SIGPIPE sometimes gets generated when CLIs disconnect from
	// tailscaled. The default action is to terminate the process, we
	// want to keep running.
	signal.Ignore(syscall.SIGPIPE)
	go func() {
		select {
		case s := <-interrupt:
			logf("tailscaled got signal %v; shutting down", s)
			cancel()
		case <-ctx.Done():
			// continue
		}
	}()

	srv := ipnserver.New(logf, logID, sys.NetMon.Get())
	if debugMux != nil {
		debugMux.HandleFunc("/debug/ipn", srv.ServeHTMLStatus)
	}
	var lbErr syncs.AtomicValue[error]
	localBackend := MyLocalBackend{}
	go func() {
		t0 := time.Now()
		if s, ok := envknob.LookupInt("TS_DEBUG_BACKEND_DELAY_SEC"); ok {
			d := time.Duration(s) * time.Second
			logf("sleeping %v before starting backend...", d)
			select {
			case <-time.After(d):
				logf("slept %v; starting backend...", d)
			case <-ctx.Done():
				return
			}
		}
		lb, err := getLocalBackend(ctx, logf, logID, sys)
		if err == nil {
			logf("got LocalBackend in %v", time.Since(t0).Round(time.Millisecond))
			srv.SetLocalBackend(lb)

			// Custom API Server
			localBackend.backend = lb
			localBackend.logf = logf
			mux := http.NewServeMux()

			// 注册路由处理函数
			mux.HandleFunc("/getIPs", localBackend.getIPsHandler)
			mux.HandleFunc("/getState", localBackend.getState)
			mux.HandleFunc("/getServiceState", localBackend.getServiceState)
			mux.HandleFunc("/login", localBackend.login)
			mux.HandleFunc("/logout", localBackend.logout)
			mux.HandleFunc("/disconnect", localBackend.disconnect)
			mux.HandleFunc("/configRouteAll", localBackend.configRouteAll)

			// 创建 HTTP 服务端
			server := &http.Server{
				Addr:    ":8090",
				Handler: mux,
			}

			// 启动服务
			go server.ListenAndServe()
			logf("start Custom API on %s", server.Addr)

			// try first login on start
			if globalConfig.AutoConnect {
				logf("start first login...")
				e := localBackend.doLogin(30 * time.Second)
				if e != nil {
					logf("first login with err %s", e.Error())
				} else {
					logf("first login done")
				}
			} else {
				logf("SKIP_AUTO_LOGIN")
			}
			return
		}
		lbErr.Store(err) // before the following cancel
		cancel()         // make srv.Run below complete
	}()

	err = srv.Run(ctx, ln)

	if err != nil && lbErr.Load() != nil {
		return fmt.Errorf("getLocalBackend error: %v", lbErr.Load())
	}

	// Cancelation is not an error: it is the only way to stop ipnserver.
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("ipnserver.Run: %w", err)
	}

	return nil
}

func getLocalBackend(ctx context.Context, logf logger.Logf, logID logid.PublicID, sys *tsd.System) (_ *ipnlocal.LocalBackend, retErr error) {
	if logPol != nil {
		logPol.Logtail.SetNetMon(sys.NetMon.Get())
	}

	socksListener, httpProxyListener := mustStartProxyListeners(args.socksAddr, args.httpProxyAddr)

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	sys.Set(dialer)

	onlyNetstack, err := createEngine(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("createEngine: %w", err)
	}
	if debugMux != nil {
		if ms, ok := sys.MagicSock.GetOK(); ok {
			debugMux.HandleFunc("/debug/magicsock", ms.ServeHTTPDebug)
		}
		go runDebugServer(debugMux, args.debug)
	}

	ns, err := newNetstack(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = onlyNetstack
	ns.ProcessSubnets = onlyNetstack || handleSubnetsInNetstack()

	if onlyNetstack {
		e := sys.Engine.Get()
		dialer.UseNetstackForIP = func(ip netip.Addr) bool {
			_, ok := e.PeerForIP(ip)
			return ok
		}
		dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return ns.DialContextTCP(ctx, dst)
		}
	}
	if socksListener != nil || httpProxyListener != nil {
		var addrs []string
		if httpProxyListener != nil {
			hs := &http.Server{Handler: httpProxyHandler(dialer.UserDial)}
			go func() {
				log.Fatalf("HTTP proxy exited: %v", hs.Serve(httpProxyListener))
			}()
			addrs = append(addrs, httpProxyListener.Addr().String())
		}
		if socksListener != nil {
			ss := &socks5.Server{
				Logf:   logger.WithPrefix(logf, "socks5: "),
				Dialer: dialer.UserDial,
			}
			go func() {
				log.Fatalf("SOCKS5 server exited: %v", ss.Serve(socksListener))
			}()
			addrs = append(addrs, socksListener.Addr().String())
		}
		tshttpproxy.SetSelfProxy(addrs...)
	}

	opts := ipnServerOpts()

	store, err := store.New(logf, statePathOrDefault())
	if err != nil {
		return nil, fmt.Errorf("store.New: %w", err)
	}
	sys.Set(store)

	lb, err := ipnlocal.NewLocalBackend(logf, logID, sys, opts.LoginFlags)
	if err != nil {
		return nil, fmt.Errorf("ipnlocal.NewLocalBackend: %w", err)
	}
	lb.SetVarRoot(opts.VarRoot)
	if logPol != nil {
		lb.SetLogFlusher(logPol.Logtail.StartFlush)
	}
	if root := lb.TailscaleVarRoot(); root != "" {
		dnsfallback.SetCachePath(filepath.Join(root, "derpmap.cached.json"), logf)
	}
	lb.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})
	configureTaildrop(logf, lb)
	if err := ns.Start(lb); err != nil {
		log.Fatalf("failed to start netstack: %v", err)
	}
	return lb, nil
}

// createEngine tries to the wgengine.Engine based on the order of tunnels
// specified in the command line flags.
//
// onlyNetstack is true if the user has explicitly requested that we use netstack
// for all networking.
func createEngine(logf logger.Logf, sys *tsd.System) (onlyNetstack bool, err error) {
	if args.tunname == "" {
		return false, errors.New("no --tun value specified")
	}
	var errs []error
	for _, name := range strings.Split(args.tunname, ",") {
		logf("wgengine.NewUserspaceEngine(tun %q) ...", name)
		onlyNetstack, err = tryEngine(logf, sys, name)
		if err == nil {
			return onlyNetstack, nil
		}
		logf("wgengine.NewUserspaceEngine(tun %q) error: %v", name, err)
		errs = append(errs, err)
	}
	return false, multierr.New(errs...)
}

// handleSubnetsInNetstack reports whether netstack should handle subnet routers
// as opposed to the OS. We do this if the OS doesn't support subnet routers
// (e.g. Windows) or if the user has explicitly requested it (e.g.
// --tun=userspace-networking).
func handleSubnetsInNetstack() bool {
	if v, ok := envknob.LookupBool("TS_DEBUG_NETSTACK_SUBNETS"); ok {
		return v
	}
	if distro.Get() == distro.Synology {
		return true
	}
	switch runtime.GOOS {
	case "windows", "darwin", "freebsd", "openbsd":
		// Enable on Windows and tailscaled-on-macOS (this doesn't
		// affect the GUI clients), and on FreeBSD.
		return true
	}
	return false
}

var tstunNew = tstun.New

func tryEngine(logf logger.Logf, sys *tsd.System, name string) (onlyNetstack bool, err error) {
	conf := wgengine.Config{
		ListenPort:   args.port,
		NetMon:       sys.NetMon.Get(),
		Dialer:       sys.Dialer.Get(),
		SetSubsystem: sys.Set,
	}

	onlyNetstack = name == "userspace-networking"
	netstackSubnetRouter := onlyNetstack // but mutated later on some platforms
	netns.SetEnabled(!onlyNetstack)

	if args.birdSocketPath != "" && createBIRDClient != nil {
		log.Printf("Connecting to BIRD at %s ...", args.birdSocketPath)
		conf.BIRDClient, err = createBIRDClient(args.birdSocketPath)
		if err != nil {
			return false, fmt.Errorf("createBIRDClient: %w", err)
		}
	}
	if onlyNetstack {
		if runtime.GOOS == "linux" && distro.Get() == distro.Synology {
			// On Synology in netstack mode, still init a DNS
			// manager (directManager) to avoid the health check
			// warnings in 'tailscale status' about DNS base
			// configuration being unavailable (from the noop
			// manager). More in Issue 4017.
			// TODO(bradfitz): add a Synology-specific DNS manager.
			conf.DNS, err = dns.NewOSConfigurator(logf, "") // empty interface name
			if err != nil {
				return false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
			}
		}
	} else {
		dev, devName, err := tstunNew(logf, name)
		if err != nil {
			tstun.Diagnose(logf, name, err)
			return false, fmt.Errorf("tstun.New(%q): %w", name, err)
		}
		conf.Tun = dev
		if strings.HasPrefix(name, "tap:") {
			conf.IsTAP = true
			e, err := wgengine.NewUserspaceEngine(logf, conf)
			if err != nil {
				return false, err
			}
			sys.Set(e)
			return false, err
		}

		r, err := router.New(logf, dev, sys.NetMon.Get())
		if err != nil {
			dev.Close()
			return false, fmt.Errorf("creating router: %w", err)
		}

		d, err := dns.NewOSConfigurator(logf, devName)
		if err != nil {
			dev.Close()
			r.Close()
			return false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
		}
		conf.DNS = d
		conf.Router = r
		if handleSubnetsInNetstack() {
			conf.Router = netstack.NewSubnetRouterWrapper(conf.Router)
			netstackSubnetRouter = true
		}
		sys.Set(conf.Router)
	}
	e, err := wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		return onlyNetstack, err
	}
	e = wgengine.NewWatchdog(e)
	sys.Set(e)
	sys.NetstackRouter.Set(netstackSubnetRouter)

	return onlyNetstack, nil
}

func newDebugMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/metrics", servePrometheusMetrics)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func servePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	varz.Handler(w, r)
	clientmetric.WritePrometheusExpositionFormat(w)
}

func runDebugServer(mux *http.ServeMux, addr string) {
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func newNetstack(logf logger.Logf, sys *tsd.System) (*netstack.Impl, error) {
	return netstack.Create(logf, sys.Tun.Get(), sys.Engine.Get(), sys.MagicSock.Get(), sys.Dialer.Get(), sys.DNSManager.Get())
}

// mustStartProxyListeners creates listeners for local SOCKS and HTTP
// proxies, if the respective addresses are not empty. socksAddr and
// httpAddr can be the same, in which case socksListener will receive
// connections that look like they're speaking SOCKS and httpListener
// will receive everything else.
//
// socksListener and httpListener can be nil, if their respective
// addrs are empty.
func mustStartProxyListeners(socksAddr, httpAddr string) (socksListener, httpListener net.Listener) {
	if socksAddr == httpAddr && socksAddr != "" && !strings.HasSuffix(socksAddr, ":0") {
		ln, err := net.Listen("tcp", socksAddr)
		if err != nil {
			log.Fatalf("proxy listener: %v", err)
		}
		return proxymux.SplitSOCKSAndHTTP(ln)
	}

	var err error
	if socksAddr != "" {
		socksListener, err = net.Listen("tcp", socksAddr)
		if err != nil {
			log.Fatalf("SOCKS5 listener: %v", err)
		}
		if strings.HasSuffix(socksAddr, ":0") {
			// Log kernel-selected port number so integration tests
			// can find it portably.
			log.Printf("SOCKS5 listening on %v", socksListener.Addr())
		}
	}
	if httpAddr != "" {
		httpListener, err = net.Listen("tcp", httpAddr)
		if err != nil {
			log.Fatalf("HTTP proxy listener: %v", err)
		}
		if strings.HasSuffix(httpAddr, ":0") {
			// Log kernel-selected port number so integration tests
			// can find it portably.
			log.Printf("HTTP proxy listening on %v", httpListener.Addr())
		}
	}

	return socksListener, httpListener
}

var beChildFunc = beChild

func beChild(args []string) error {
	if len(args) == 0 {
		return errors.New("missing mode argument")
	}
	typ := args[0]
	f, ok := childproc.Code[typ]
	if !ok {
		return fmt.Errorf("unknown be-child mode %q", typ)
	}
	return f(args[1:])
}

// IPN Custom Handlers
type CustomResp struct {
	Data map[string]any `json:"data"`
	Code int64          `json:"code"`
	Msg  string         `json:"msg"`
}

func (b *MyLocalBackend) getIPsHandler(w http.ResponseWriter, r *http.Request) {
	st := b.backend.State()
	if st == ipn.Running {
		loginErr = loginErrWarpper{
			Code: 0,
			Err:  nil,
		}
	}

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
			"node_ips": ips,
		},
		Code: int64(loginErr.Code),
	}
	if loginErr.Err == nil {
		newResp.Msg = "ok"
	} else {
		newResp.Msg = loginErr.Err.Error()
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
func (b *MyLocalBackend) doLogin(timeout time.Duration) error {
	cerr := checkNslookup(globalConfig.ControlUrl)
	if cerr != nil {
		loginErr = loginErrWarpper{
			Code: 101,
			Err:  cerr,
		}
	}
	hname, _ := os.Hostname()
	suffix := "digital_guard"
	if globalConfig.HostSuffix != "" {
		suffix = globalConfig.HostSuffix
	}
	o := ipn.Options{
		AuthKey: globalConfig.AuthKey,
		UpdatePrefs: &ipn.Prefs{
			ControlURL:       globalConfig.ControlUrl,
			WantRunning:      true,
			RouteAll:         true,
			CorpDNS:          false,
			NetfilterMode:    preftype.NetfilterOn,
			AllowSingleHosts: true,
			Hostname:         hname + suffix,
		},
	}
	adRoutes := []netip.Prefix{}
	for _, v := range globalConfig.AdvertiseRoutes {
		pp, ee := netip.ParsePrefix(v)
		if ee == nil {
			adRoutes = append(adRoutes, pp)
		}
	}
	if len(adRoutes) > 0 {
		o.UpdatePrefs.AdvertiseRoutes = adRoutes
	}
	var loginOnce sync.Once
	startLoginInteractive := func() { loginOnce.Do(func() { b.backend.StartLoginInteractive() }) }

	err := b.backend.Start(o)
	if err == nil {
		ticker := time.NewTicker(2 * time.Second)
		deadline := time.After(timeout)
		defer ticker.Stop()
		/*
			if err == nil && initStatus == ipn.NeedsLogin {
				b.backend.StartLoginInteractive()
			}
		*/
	Loop:
		for {
			select {
			case <-ticker.C:
				if b.backend.State() == ipn.NeedsLogin {
					startLoginInteractive()
				} else if b.backend.State() == ipn.Running {
					break Loop
				}
			case <-deadline:
				err = errors.New("Start TimeOut")
				break Loop
			}
		}
	}
	if err != nil {
		loginErr = loginErrWarpper{
			Code: 102,
			Err:  err,
		}
	} else {
		loginErr = loginErrWarpper{
			Code: 0,
			Err:  nil,
		}
	}
	var checkProcessExistence sync.Once
	checkProcessExistenceLoop := func() {
		checkProcessExistence.Do(func() {
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						if len(globalConfig.ProcessExistence) > 0 {
							exists, err := processExists(globalConfig.ProcessExistence)
							if err != nil {
								b.logf("轮询进程存在性报错: %s", err.Error())
							}
							if exists {
								b.logf("进程 %s 存在\n", globalConfig.ProcessExistence)
							} else if b.backend.State() == ipn.Running {
								b.logf("进程 %s 不存在,断开连接\n", globalConfig.ProcessExistence)
								//断开连接 同disconnect
								mp := ipn.MaskedPrefs{
									Prefs: ipn.Prefs{
										WantRunning: false,
									},
									WantRunningSet: true,
								}
								b.backend.EditPrefs(&mp)
							}
						}
					}
				}
			}()
		})
	}
	checkProcessExistenceLoop()
	return err
}
func (b *MyLocalBackend) login(w http.ResponseWriter, r *http.Request) {
	err := b.doLogin(15 * time.Second)
	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	//prefs := b.backend.Prefs()
	//res := prefs.AsStruct()
	newResp := &CustomResp{
		Data: map[string]any{
			//"prefs": res,
		},
		Code: 0,
		Msg:  "ok",
	}
	response, _ := json.Marshal(newResp)
	if err != nil {
		newResp.Code = -1
		newResp.Msg = err.Error()
	}
	// 发送 JSON 响应
	w.Write(response)
}

func (b *MyLocalBackend) disconnect(w http.ResponseWriter, r *http.Request) {
	var response []byte
	if b.backend.State() != ipn.Running {
		newResp := &CustomResp{
			Data: map[string]any{
				//"prefs": prefs,
			},
			Code: 100,
			Msg:  "Not login yet",
		}
		response, _ = json.Marshal(newResp)
		b.logf("不处于运行状态\n")
	} else {
		mp := ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				WantRunning: false,
			},
			WantRunningSet: true,
		}
		//prefs, err := b.backend.EditPrefs(&mp)
		_, err := b.backend.EditPrefs(&mp)
		newResp := &CustomResp{
			Data: map[string]any{
				//"prefs": prefs,
			},
			Code: 0,
			Msg:  "ok",
		}
		response, _ = json.Marshal(newResp)
		if err != nil {
			newResp.Code = -1
			newResp.Msg = err.Error()
		}
		b.logf("断开连接:%s\n", err)
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	// 发送 JSON 响应
	w.Write(response)
}

func (b *MyLocalBackend) logout(w http.ResponseWriter, r *http.Request) {
	err := b.backend.LogoutSync(context.Background())

	newResp := &CustomResp{
		Data: map[string]any{},
		Code: 0,
		Msg:  "ok",
	}
	response, _ := json.Marshal(newResp)
	if err != nil {
		newResp.Code = -1
		newResp.Msg = err.Error()
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	// 发送 JSON 响应
	w.Write(response)
}

func (b *MyLocalBackend) getState(w http.ResponseWriter, r *http.Request) {
	st := b.backend.State()

	newResp := &CustomResp{
		Data: map[string]any{
			"states": st.String(),
		},
		Code: 0,
		Msg:  "ok",
	}
	response, _ := json.Marshal(newResp)

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	// 发送 JSON 响应
	w.Write(response)
}

func (b *MyLocalBackend) getServiceState(w http.ResponseWriter, r *http.Request) {
	serviceSt, err := getWindowsServiceState()

	newResp := &CustomResp{
		Data: map[string]any{
			"service_state": serviceSt,
		},
		Code: 0,
		Msg:  "ok",
	}
	if err != nil {
		newResp.Code = -1
		newResp.Msg = err.Error()
		newResp.Data = map[string]any{}
	}
	response, _ := json.Marshal(newResp)

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	// 发送 JSON 响应
	w.Write(response)
}

func (b *MyLocalBackend) configRouteAll(w http.ResponseWriter, r *http.Request) {
	enable := r.URL.Query().Get("enable")
	var routeAll bool
	if enable == "-1" {
		routeAll = false
	} else {
		routeAll = true
	}
	newResp := &CustomResp{
		Data: map[string]any{},
		Code: 0,
		Msg:  "ok",
	}
	prefs := b.backend.Prefs()
	if prefs.RouteAll() == routeAll {
		newResp.Data["prefs.routeAll"] = prefs.RouteAll()
		newResp.Msg = "No change set"
		newResp.Code = 0
	} else {
		mp := ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				RouteAll: routeAll,
			},
			RouteAllSet: true,
		}
		newPrefs, err := b.backend.EditPrefs(&mp)
		if err != nil {
			newResp.Code = -1
			newResp.Data["prefs.routeAll"] = prefs.RouteAll()
			newResp.Msg = err.Error()
		} else {
			newResp.Code = 0
			newResp.Data["prefs.routeAll"] = newPrefs.RouteAll()
			newResp.Msg = "ok"
		}
	}

	response, _ := json.Marshal(newResp)
	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	// 发送 JSON 响应
	w.Write(response)
}

func checkNslookup(domain string) error {
	parsedURL, err := url.Parse(domain)
	if err != nil {
		return err
	}
	host := parsedURL.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("dns resolv failed")
	}
	return nil
}

func processExists(processName string) (bool, error) {
	processes, err := process.Processes()
	if err != nil {
		return false, err
	}

	for _, p := range processes {
		executable, _ := p.Exe()

		if strings.Contains(executable, processName) {
			return true, nil
		}
	}

	return false, nil
}
