package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/tuannt/multi-anti/internal/cli"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.Config{
		Version: version,
	})
	stop()
	os.Exit(code)
}
