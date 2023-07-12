/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/tailscale/wireguard-go/device"
	"gopkg.in/yaml.v2"
	"tailscale.com/net/dns"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

var b *backend

func GetAppPath() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)

	return path
}
func GetAppDirectory() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))

	return path[:index]
}

var logf logger.Logf = log.Printf
var globalCfg *Config

const ConfigFile = "config.yaml"

func main() {
	cfg, err := GetConfig(ConfigFile)
	if err != nil {
		logf(err.Error())
		return
	}
	globalCfg = cfg
	// 创建一个上下文对象和取消函数
	ctx, cancel := context.WithCancel(context.Background())

	// 创建一个通道来接收操作系统的信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	wg := sync.WaitGroup{}
	// 启动一个 goroutine 监听信号
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case sig := <-sigChan:
				switch sig {
				case os.Interrupt, syscall.SIGTERM:
					logf("Received termination signal. Gracefully shutting down...")
					cancel() // 发出取消信号，触发优雅退出
				}
			case <-ctx.Done():
				logf("Cleanup resources...")
				time.Sleep(2 * time.Second)
				logf("Program gracefully exited.")
				return
			}
		}
	}()
	dataDir := GetAppDirectory()
	miraStartEngine(dataDir)
	// 等待程序退出完成
	wg.Wait()
}
func miraStartEngine(path string) int32 {
	if b != nil {
		return 0
	}
	deviceLogger := &device.Logger{
		Verbosef: logf,
		Errorf:   logf,
	}

	errf, err := os.Create(path + "/output.txt")
	if err != nil {
		deviceLogger.Errorf("Error create output file: %v", err)
	}
	os.Stdout = errf
	os.Stderr = errf

	b, err = newBackend(path, deviceLogger.Errorf, setBoth)
	if err != nil {
		deviceLogger.Errorf("Unable to create backend: %v", err)
		return -1
	}
	b.RunLocalAPIServer()
	b.RunLocalCustomServer()
	go runBackend()
	return 0
}

type addrDisplay struct {
	V4AddrsStrs  []string
	V6AddrsStrs  []string
	V4RoutesStrs []string
	V6RoutesStrs []string
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
	js := &addrDisplay{
		V4AddrsStrs:  v4AddrsStrs,
		V6AddrsStrs:  v6AddrsStrs,
		V4RoutesStrs: v4RoutesStrs,
		V6RoutesStrs: v6RoutesStrs,
	}
	bs, _ := json.MarshalIndent(js, "", "  ")
	fmt.Printf("%s\n", bs)
	return nil
}

type Config struct {
	ControlUrl string `yaml:"controlUrl"`
	AuthKey    string `yaml:"authKey"`
	DataDir    string `yaml:"dataDir"`
}

func GetConfig(filename string) (*Config, error) {
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
