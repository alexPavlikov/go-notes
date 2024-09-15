package main

import (
	"log/slog"

	"github.com/alexPavlikov/go-notes/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		slog.Error("main error", "error", err)
		return
	}
}
