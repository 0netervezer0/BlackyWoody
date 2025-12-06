package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	ClearTerminal()
	fmt.Print(
		"\u001b[31m                                     _\n",
		"_-_ _,,   ,,            ,,          - - /, /,              |\\\n",
		"   -/  )  ||   _        ||            )/ )/ )               \\\\\n",
		"  ~||_<   ||  < \\,  _-_ ||/\\ '\\\\/\\\\   )__)__)  /'\\\\  /'\\\\  / \\\\ '\\\\/\\\\\n",
		"   || \\\\  ||  /-|| ||   ||_<  || ;'  ~)__)__) || || || || || ||  || ;'\n",
		"   ,/--|| || (( || ||   || |  ||/     )  )  ) || || || || || ||  ||/\n",
		"  _--_-'  \\\\  \\/\\\\ \\\\,/ \\\\,\\  |/     /-_/-_/  \\\\,/  \\\\,/   \\\\/   |/\n",
		" (                           (                                  (\n",
		"                              -_-                                -_-\u001b[0m\n")

	if len(os.Args) < 2 {
		usage()
		return
	}

	mode := os.Args[1]

	if mode == "getip" {
		showLocalIPs()
		return
	}

	name := askName(mode)

	ctx, cancel := signalContext()
	defer cancel()

	switch mode {
	case "listen":
		if len(os.Args) != 3 {
			fmt.Println("Usage: woody listen <port>")
			return
		}
		port := os.Args[2]
		if err := listenMode(ctx, port, name); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
	case "connect":
		if len(os.Args) != 3 {
			fmt.Println("Usage: woody connect <ip:port>")
			return
		}
		addr := os.Args[2]
		if err := connectMode(ctx, addr, name); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
	default:
		usage()
	}
}

func ClearTerminal() {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd = exec.Command("clear")
	} else {
		fmt.Println("Error: your OS is not supported")
		return
	}

	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Run()
}

func usage() {
	fmt.Println("P2P terminal messenger")
	fmt.Println("Usage:")
	fmt.Println("  woody getip")
	fmt.Println("  woody listen <port>")
	fmt.Println("  woody connect <ip:port>")
}

// askName prompts user for a display name
func askName(mode string) string {
	fmt.Print("Your nickname: ")
	r := bufio.NewReader(os.Stdin)
	n, _ := r.ReadString('\n')
	n = strings.TrimSpace(n)
	if n == "" {
		if mode == "listen" {
			n = "Host"
		}
		if mode == "connect" {
			n = "Client"
		}
	}
	return n
}

// signalContext returns a context that cancels on SIGINT/SIGTERM
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cancel()
	}()
	return ctx, cancel
}

func listenMode(ctx context.Context, port, name string) error {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	fmt.Printf("Waiting for connection to: %s\n", port)

	type result struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		resCh <- result{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil
	case r := <-resCh:
		if r.err != nil {
			return r.err
		}
		defer r.conn.Close()
		fmt.Println("Client connected:", r.conn.RemoteAddr())
		return handleConn(ctx, r.conn, name)
	}
}

func connectMode(ctx context.Context, addr, name string) error {
	fmt.Println("Connecting to", addr)
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	fmt.Println("Successfully connected to", conn.RemoteAddr())
	return handleConn(ctx, conn, name)
}

// handleConn performs simple name exchange then runs send/receive loops
func handleConn(ctx context.Context, conn net.Conn, myName string) error {
	// set deadlines to avoid stuck Read on closed socket (optional)
	_ = conn.SetReadDeadline(time.Time{}) // clear any deadline

	// Exchange names: each side sends its name as the first line.
	// This works because both sides will write then read (race is fine).
	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	// Send my name
	if _, err := writer.WriteString(myName + "\n"); err != nil {
		return fmt.Errorf("send name: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush name: %w", err)
	}

	// Read peer name (first line)
	peerNameRaw, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read peer name: %w", err)
	}
	peerName := strings.TrimSpace(peerNameRaw)
	if peerName == "" {
		peerName = "Peer"
	}
	fmt.Printf("The name exchange is complete. Interlocutor: %s\n", peerName)
	fmt.Println("To close the connection type '/exit' or press 'Ctrl+C'")
	fmt.Println()

	// Channels and wait group for goroutines
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Receiving goroutine
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			default:
				// read a line from peer
				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						fmt.Println("\n[\u001b[31mBlackyWoody\u001b[0m] Connection lost")
					} else {
						fmt.Println("\n[\u001b[31mBlackyWoody\u001b[0m] Reading error:", err)
					}
					// signal sender to stop
					close(done)
					return
				}
				line = strings.TrimRight(line, "\r\n")
				// print with peer name and timestamp
				fmt.Printf("\r[\u001b[38;5;88m%s\u001b[0m] [%s]: %s\n", peerName, timeNow(), line)
				// reprint prompt marker if needed
				fmt.Print("> ")
			}
		}
	}()

	// Sending goroutine (reads from stdin)
	go func() {
		defer wg.Done()
		stdin := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("> ")
			text, err := stdin.ReadString('\n')
			if err != nil {
				// stdin closed or error
				fmt.Println("\n[\u001b[31mBlackyWoody\u001b[0m] Input is closed")
				close(done)
				return
			}
			text = strings.TrimRight(text, "\r\n")
			if text == "/exit" {
				close(done)
				return
			}
			// prepare and send
			if _, err := writer.WriteString(text + "\n"); err != nil {
				fmt.Println("\n[\u001b[31mBlackyWoody\u001b[0m] Sending error:", err)
				close(done)
				return
			}
			if err := writer.Flush(); err != nil {
				fmt.Println("\n[\u001b[31mBlackyWoody\u001b[0m] Flush error:", err)
				close(done)
				return
			}
		}
	}()

	// Wait for context cancellation (Ctrl+C) or done channel
	select {
	case <-ctx.Done():
		// user pressed Ctrl+C
		fmt.Println("\n[\u001b[31mBlackyWoody\u001b[0m] Finishing by signal")
	case <-done:
		// connection closed or /exit
	}

	// close connection and wait goroutines
	_ = conn.Close()
	// ensure done closed so goroutines exit
	select {
	case <-done:
	default:
		close(done)
	}
	wg.Wait()
	fmt.Println("[\u001b[31mBlackyWoody\u001b[0m] Session is finished")
	return nil
}

func timeNow() string {
	return time.Now().Format("15:04:05")
}

func showLocalIPs() {
	ips, err := getLocalIPs()
	if err != nil {
		fmt.Println("Error of getting IP:", err)
		return
	}

	fmt.Println("Your IP-adresses:")
	for _, ip := range ips {
		fmt.Println(" -", ip)
	}
}

func getLocalIPs() ([]string, error) {
	var ips []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue
			}

			ips = append(ips, ip.String())
		}
	}

	return ips, nil
}
