package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	colorRed   = "\u001b[31m"
	colorPeer  = "\u001b[38;5;88m"
	colorReset = "\u001b[0m"

	tag = "BlackyWoody"
)

func main() { 
	clearTerminal()
	printBanner()

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
		if err := listenMode(ctx, os.Args[2], name); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}

	case "connect":
		if len(os.Args) != 3 {
			fmt.Println("Usage: woody connect <ip:port>")
			return
		}
		if err := connectMode(ctx, os.Args[2], name); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}

	default:
		usage()
	}
}

func clearTerminal() {
	fmt.Print("\033[2J\033[H")
}

func printBanner() {
	fmt.Print(colorRed,
		"                                     _\n",
		"_-_ _,,   ,,            ,,          - - /, /,              |\\\n",
		"   -/  )  ||   _        ||            )/ )/ )               \\\\\n",
		"  ~||_<   ||  < \\,  _-_ ||/\\ '\\\\/\\\\   )__)__)  /'\\\\  /'\\\\  / \\\\ '\\\\/\\\\\n",
		"   || \\\\  ||  /-|| ||   ||_<  || ;'  ~)__)__) || || || || || ||  || ;'\n",
		"   ,/--|| || (( || ||   || |  ||/     )  )  ) || || || || || ||  ||/\n",
		"  _--_-'  \\\\  \\/\\\\ \\\\,/ \\\\,\\  |/     /-_/-_/  \\\\,/  \\\\,/   \\\\/   |/\n",
		" (                           (                                  (\n",
		"                              -_-                                -_-\n",
		colorReset)
}

func usage() {
	fmt.Println("P2P terminal messenger")
	fmt.Println("Usage:")
	fmt.Println("  woody getip")
	fmt.Println("  woody listen <port>")
	fmt.Println("  woody connect <ip:port>")
}

func askName(mode string) string {
	fmt.Print("Your nickname: ")
	r := bufio.NewReader(os.Stdin)
	n, _ := r.ReadString('\n')
	n = strings.TrimSpace(n)

	if n == "" {
		if mode == "listen" {
			n = "Host"
		} else {
			n = "Client"
		}
	}
	
	return n
}

func askPassword() string {
	fmt.Print("Shared password: ")
	r := bufio.NewReader(os.Stdin)
	p, _ := r.ReadString('\n')
	
	return strings.TrimSpace(p)
}

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
	// Ask host for the shared password before accepting connections
	password := askPassword()
	if password == "" {
		return fmt.Errorf("empty password")
	}
	
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	defer ln.Close()

	fmt.Println("Waiting for connection on port:", port)

	type result struct {
		conn net.Conn
		err  error
	}

	resCh := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		resCh <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		fmt.Printf("\n[%s%s%s] Cancelled\n", colorRed, tag, colorReset)
		return nil

	case res := <-resCh:
		if res.err != nil {
			return res.err
		}
		defer res.conn.Close()

		fmt.Println("Client connected:", res.conn.RemoteAddr())
		return handleConn(ctx, res.conn, name, true, password)

	}
}

func connectMode(ctx context.Context, addr, name string) error {
	fmt.Println("Connecting to", addr)

	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Println("Connected to", conn.RemoteAddr())
    
	// client will be prompted for password inside handleConn
	return handleConn(ctx, conn, name, false, "")

}

func handleConn(ctx context.Context, conn net.Conn, myName string, isServer bool, password string) error {
	if password == "" {
		password = askPassword()
		if password == "" {
			return fmt.Errorf("empty password")
		}
	}

	secure, err := NewSecureConn(conn, conn, password, isServer)
	if err != nil {
		return fmt.Errorf("secure handshake failed: %w", err)
	}

	if err := secure.WriteMessage(myName); err != nil {
		return err
	}

	peerName, err := secure.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read peer name")
	}
	if peerName == "" {
		peerName = "Peer"
	}

	fmt.Println("Interlocutor:", peerName)
	fmt.Println("")

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			close(done)
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// ================= RECEIVER =================
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				closeDone()
				return
			case <-done:
				return
			default:
				msg, err := secure.ReadMessage()
				if err != nil {
					fmt.Printf(
						"\n[%s%s%s] Сhannel closed\n",
						colorRed, tag, colorReset,
					)
					fmt.Printf(
						"[%s%s%s] Session finished\n",
						colorRed, tag, colorReset,
					)
					os.Exit(0)
				}

				// Render formatting markup to ANSI for display
				formatted := formatMessage(msg)
				fmt.Printf(
					"\r[%s%s%s] [%s]: %s\n> ",
					colorPeer, peerName, colorReset,
					timeNow(), formatted,
				)
			}
		}
	}()

	// ================= SENDER =================
	go func() {
		defer wg.Done()

		stdin := bufio.NewReader(os.Stdin)

		for {
			fmt.Print("> ")
			text, err := stdin.ReadString('\n')
			if err != nil {
				closeDone()
				return
			}

			text = strings.TrimSpace(text)
			if text == "/exit" {
				closeDone()
				return
			}

			if err := secure.WriteMessage(text); err != nil {
				fmt.Printf(
					"\n[%s%s%s] Send failed\n",
					colorRed, tag, colorReset,
				)
				closeDone()
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}

	closeDone()
	_ = conn.Close()
	wg.Wait()

	fmt.Printf(
		"[%s%s%s] Session finished\n",
		colorRed, tag, colorReset,
	)
	return nil
}


func timeNow() string {
	return time.Now().Format("15:04:05")
}

// formatMessage converts simple markdown-like markup into ANSI sequences:
// - ***bold italic***, **bold**, *italic*
// - $<color>$...$reset$ (named color from the map; case-insensitive)
func formatMessage(s string) string {
	if s == "" {
		return s
	}

	// triple stars -> bold + italic (use specific off-codes so color isn't reset)
	// bold on: 1, off: 22; italic on: 3, off: 23
	reTriple := regexp.MustCompile(`\*\*\*(.+?)\*\*\*`)
	s = reTriple.ReplaceAllString(s, "\u001b[1m\u001b[3m$1\u001b[23m\u001b[22m")

	// bold (off: 22)
	reBold := regexp.MustCompile(`\*\*(.+?)\*\*`)
	s = reBold.ReplaceAllString(s, "\u001b[1m$1\u001b[22m")

	// italic (off: 23)
	reItalic := regexp.MustCompile(`\*(.+?)\*`)
	s = reItalic.ReplaceAllString(s, "\u001b[3m$1\u001b[23m")

	colorMap := map[string]string{
		"red":    "\u001b[31m",
		"orange": "\u001b[38;5;208m",
		"yellow": "\u001b[33m",
		"green":  "\u001b[32m",
		"blue":   "\u001b[34m",
		"indigo": "\u001b[38;5;54m",
		"violet": "\u001b[35m",
		"magenta":"\u001b[35m",
	}

	reColor := regexp.MustCompile(`\$([a-zA-Z]+)\$(.+?)\$reset\$`)
	s = reColor.ReplaceAllStringFunc(s, func(m string) string {
		sub := reColor.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		name := strings.ToLower(sub[1])
		text := sub[2]
		if code, ok := colorMap[name]; ok {
			return code + text + colorReset
		}
		// unknown color: strip markers and return inner text
		return text
	})

	return s
}

func showLocalIPs() {
	ips, _ := getLocalIPs()
	fmt.Println("Your IP addresses:")
	for _, ip := range ips {
		fmt.Println(" -", ip)
	}
}

func getLocalIPs() ([]string, error) {
	var ips []string
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil {
					ips = append(ips, ip.String())
				}
			}
		}
	}
	
	return ips, nil
}
