package main

import (
	"github.com/moldabekov/spinner"
	"time"
)

func loader(s string) {
	spin := spinner.New("%s " + s)
	spin.Start()
	defer spin.Stop()
	time.Sleep(30 * time.Second) // query every 30 seconds
}
