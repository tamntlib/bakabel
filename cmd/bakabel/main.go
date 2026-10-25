package main

import (
	"context"
	"github.com/tamntlib/bakabel/internal/app"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(app.Main(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
