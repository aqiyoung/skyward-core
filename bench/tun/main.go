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
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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

// outgoingAddress is the address of the interface the machine reaches the
// world by. The core binds its own outbound to that interface, so a node on
// the loopback is one it cannot reach.
func outgoingAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagUp == 0 || item.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := item.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if network, ok := address.(*net.IPNet); ok && network.IP.To4() != nil {
				return network.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

func main() {
	configPath := flag.String("config", "", "the configuration to measure")
	device := flag.String("device", "skyward-bench", "the tunnel device")
	runs := flag.Int("runs", 9, "how many measured transfers")
	warmup := flag.Int("warmup", 1, "how many unmeasured transfers to discard before the first run")
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
	// The configuration names the loopback for the node, which the core
	// cannot reach while it binds its outbound to the machine's interface.
	node := outgoingAddress()
	patched := strings.Replace(string(config), "server: 127.0.0.1", "server: "+node, 1)
	cfg, err := executor.ParseWithBytes([]byte(patched))
	if err != nil {
		panic(err)
	}
	executor.ApplyConfig(cfg, true)
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
	proxy, err := net.Listen("tcp", fmt.Sprintf("%s:%d", outgoingAddress(), proxyPort))
	if err != nil {
		panic(err)
	}
	defer proxy.Close()
	go serveProxy(proxy)

	// The executor leaves the tunnel device to the application, and the go
	// stack hands it over down. A down interface cannot be a nexthop, so
	// bring it up before pointing a route at it. The legacy stack already
	// has it up, and setting IFF_UP twice is harmless.
	linkUp(*device)

	// Only the address the client asks for is routed into the tunnel.
	route(true, *device)
	defer route(false, *device)

	// The core runs in fake-ip mode: it expects the client to ask for a
	// name, so that it can hand out an address and remember the mapping.
	// A literal address is one it never handed out, and the connection is
	// dropped before it begins.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "udp", "127.0.0.1:1053")
		},
	}
	addresses, err := resolver.LookupHost(context.Background(), "bench.invalid")
	if err != nil {
		fmt.Fprintln(os.Stderr, "the core's DNS did not answer:", err)
		os.Exit(1)
	}
	url := fmt.Sprintf("http://%s:%d/payload.bin", addresses[0], targetPort)
	fmt.Printf("device=%s runs=%d warmup=%d size=%dMiB\n", *device, *runs, *warmup, *sizeMiB)

	transfer := func() (float64, int64, time.Duration) {
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
		return float64(read) / 1048576 / elapsed.Seconds(), read, elapsed
	}

	// The first transfers warm caches and the sender's congestion window.
	// Legacy stacks rose on every one of the first three runs while the go
	// stack did not, so counting those transfers biased the comparison.
	for w := 1; w <= *warmup; w++ {
		speed, read, elapsed := transfer()
		fmt.Printf("warmup %d: %.1f MiB/s (%d bytes in %s)\n", w, speed, read, elapsed.Round(time.Millisecond))
	}

	results := make([]float64, 0, *runs)
	for run := 1; run <= *runs; run++ {
		speed, read, elapsed := transfer()
		fmt.Printf("run %d: %.1f MiB/s (%d bytes in %s)\n", run, speed, read, elapsed.Round(time.Millisecond))
		results = append(results, speed)
	}
	report(results)
}

// report makes the median the headline number and prints the spread that
// says whether that median can be trusted. Best-of-three used to be the
// verdict; it hid a warm-up ramp and said nothing about the noise.
func report(values []float64) {
	if len(values) == 0 {
		return
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)

	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	mean := sum / float64(len(sorted))
	var sq float64
	for _, v := range sorted {
		sq += (v - mean) * (v - mean)
	}
	sd := 0.0
	if len(sorted) > 1 {
		sd = math.Sqrt(sq / float64(len(sorted)-1))
	}
	cv := 0.0
	if mean > 0 {
		cv = sd / mean * 100
	}
	low, high := sorted[0], sorted[len(sorted)-1]
	spread := 0.0
	if low > 0 {
		spread = (high/low - 1) * 100
	}

	fmt.Printf("median: %.1f MiB/s\n", median)
	fmt.Printf("mean:   %.1f MiB/s\n", mean)
	fmt.Printf("stdev:  %.1f MiB/s (cv %.1f%%)\n", sd, cv)
	fmt.Printf("min:    %.1f MiB/s\n", low)
	fmt.Printf("max:    %.1f MiB/s\n", high)
	fmt.Printf("spread: %.1f%% (max/min - 1)\n", spread)
	// Kept only so existing parsers keep working; it is not the verdict.
	fmt.Printf("best:   %.1f MiB/s\n", high)
	// P0 asks for two runs within 5%. A single run whose own cv exceeds
	// that threshold is already noise and cannot settle the ratio.
	if cv <= 5 && spread <= 10 {
		fmt.Println("stable: yes (cv <= 5% and spread <= 10%)")
	} else {
		fmt.Println("stable: no (cv > 5% or spread > 10%; re-run on a quiet runner)")
	}
}

// linkUp brings the tunnel device up. The bare core leaves this to the
// application: the legacy stack sets IFF_UP itself, the go stack does not,
// and `ip route add ... dev` refuses a nexthop whose device is down.
func linkUp(device string) {
	command := exec.Command("ip", "link", "set", "dev", device, "up")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "the tunnel device could not be brought up:", err)
		os.Exit(1)
	}
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
