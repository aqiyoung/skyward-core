// Command bench measures what the tunnel costs, on one machine.
//
// The client, the core and the target all live here, so the number is the
// core's own capacity: the traffic goes through the tunnel, the rules and a
// proxy node, and never leaves the machine. That is the same shape as the
// measurement the Clash kernel publishes, and the only shape that can be
// compared across machines.
//
// Two things the bare core does not do on its own, and this program has to
// do for it: open the listeners the configuration names, and bring the
// tunnel up. The executor leaves both to the application, so a core run
// from a command line has neither.
package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel"
)

const (
	targetPort = 18080
	proxyPort  = 17891
	// The tunnel takes its address from the DNS fake-ip range, so this is
	// the address the client asks for. The tunnel's own subnet route
	// carries it, and no name is ever looked up.
	clientAddress = "198.18.0.2"
	// The range that is routed into the tunnel, so the machine's own
	// traffic is left alone.
	routeRange = "198.18.0.0/16"
)

func main() {
	configPath := flag.String("config", "", "the configuration to measure")
	device := flag.String("device", "skyward-bench", "the tunnel device")
	runs := flag.Int("runs", 3, "how many times to measure")
	sizeMiB := flag.Int("size", 64, "the payload size in MiB")
	flag.Parse()
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(2)
	}

	config, err := os.ReadFile(*configPath)
	if err != nil {
		panic(err)
	}
	cfg, err := executor.ParseWithBytes(config)
	if err != nil {
		panic(err)
	}
	if err := executor.ApplyConfig(cfg, true); err != nil {
		panic(err)
	}
	// The executor leaves the listeners and the tunnel to the application.
	// There is no application here, so this opens both.
	listener.PatchInboundListeners(cfg.Listeners, tunnel.Tunnel, true)
	listener.ReCreateTun(cfg.General.Tun, tunnel.Tunnel)
	defer listener.StopListener()

	payload := make([]byte, *sizeMiB*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		panic(err)
	}

	// The target.
	target, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		panic(err)
	}
	defer target.Close()
	go http.Serve(target, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))

	// The proxy node. It reaches the target whatever address it was asked
	// for, which is what keeps the traffic on this machine.
	proxy, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		panic(err)
	}
	defer proxy.Close()
	go serveProxy(proxy)

	// Only the address the client asks for is routed into the tunnel.
	route(true, *device)
	defer route(false, *device)

	url := fmt.Sprintf("http://%s:%d/payload.bin", clientAddress, targetPort)
	fmt.Printf("device=%s runs=%d size=%dMiB\n", *device, *runs, *sizeMiB)

	best := 0.0
	for run := 1; run <= *runs; run++ {
		start := time.Now()
		response, err := http.Get(url)
		if err != nil {
			fmt.Fprintln(os.Stderr, "the transfer failed:", err)
			os.Exit(1)
		}
		read, err := io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "the transfer failed:", err)
			os.Exit(1)
		}
		elapsed := time.Since(start)
		speed := float64(read) / 1048576 / elapsed.Seconds()
		if speed > best {
			best = speed
		}
		fmt.Printf("run %d: %.1f MiB/s (%d bytes in %s)\n", run, speed, read, elapsed.Round(time.Millisecond))
	}
	fmt.Printf("best: %.1f MiB/s\n", best)
}

// route points the measured range at the tunnel device, or puts the machine
// back the way it was.
func route(add bool, device string) {
	action := "add"
	if !add {
		action = "del"
	}
	command := exec.Command("ip", "route", action, routeRange, "dev", device)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "the route could not be set:", err)
		os.Exit(1)
	}
}

func serveProxy(listener net.Listener) {
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go handleProxy(client)
	}
}

func handleProxy(client net.Conn) {
	defer client.Close()
	request, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil {
		return
	}
	upstream, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		return
	}
	defer upstream.Close()
	if request.Method == http.MethodConnect {
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		// The request line carries the path only, so the target can serve it.
		request.URL.Scheme = ""
		request.URL.Host = ""
		request.RequestURI = ""
		if err := request.Write(upstream); err != nil {
			return
		}
	}
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
}
