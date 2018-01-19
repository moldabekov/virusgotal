package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/moldabekov/virusgotal/vt"
	"os"
)

func searchHash(hash string) {
	// Init VT
	apikey := os.Getenv("VT_API_KEY")
	vt, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// Check hash
	r, err := vt.GetFileReport(hash)
	check(err)

	if r.ResponseCode == 0 {
		color.Set(color.FgHiRed, color.Bold)
		fmt.Printf("Given hash isn't recognized by VirusTotal\n")
		color.Unset()
		os.Exit(1)
	}
	if r.Positives > 0 {
		color.Set(color.FgHiRed)
		if !*jsonHash {
			fmt.Printf("\nGiven hash is KNOWN by VirusTotal and has positive results [%d/%d]\n", r.Positives, r.Total)
		}
		printFileResult(r)
		color.Unset()
	} else {
		color.Set(color.FgHiGreen)
		fmt.Printf("\nGiven hash is KNOWN by VirusTotal and has no positive results\n")
		color.Unset()
	}
	if !*jsonHash {
		fmt.Printf("Direct link: %s\n\n", r.Permalink)
	}
}
