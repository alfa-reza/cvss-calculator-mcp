package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	mcpserver "github.com/alfa-reza/cvss-calculator-mcp/internal/mcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "1.0.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("cvss-calculator-mcp", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	transport := flags.String("transport", "stdio", "Transport: stdio or http")
	listen := flags.String("listen", "127.0.0.1:43871", "HTTP listen address")
	showVersion := flags.Bool("version", false, "Print version and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("Unexpected argument: %s", flags.Arg(0))
	}
	if *showVersion {
		fmt.Println("cvss-calculator-mcp v" + version)
		return nil
	}
	if *transport != "stdio" && *transport != "http" {
		return fmt.Errorf("Unsupported transport: %s", *transport)
	}
	listenSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			listenSet = true
		}
	})
	if *transport == "stdio" && listenSet {
		return errors.New("--listen requires --transport http")
	}
	server := mcpserver.NewServer()
	if *transport == "stdio" {
		return server.Run(context.Background(), &mcp.StdioTransport{})
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("Cannot listen: %w", err)
	}
	defer listener.Close()
	httpServer := &http.Server{Handler: mcpserver.HTTPHandler(server), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	fmt.Fprintf(os.Stderr, "CVSS Calculator MCP v%s\nTransport: Streamable HTTP\nListening: http://%s/mcp\nPress Ctrl+C to stop\n", version, listener.Addr())
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdown); err != nil {
			return err
		}
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
