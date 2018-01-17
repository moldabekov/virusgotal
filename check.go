package main

import (
	"fmt"
	"os"
)

func check(err error) {
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
}
