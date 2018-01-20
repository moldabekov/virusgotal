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

	if r.ResponseCode == 0 { // Hash not found
		color.Set(color.FgHiRed, color.Bold)
		fmt.Printf("Given hash isn't recognized by VirusTotal\n")
		color.Unset()
		os.Exit(1)
	}
	if r.ResponseCode == -2 { // File scan with given hash is still in progress
		color.Set(color.FgHiYellow)
		fmt.Printf("\nScan with given hash is still in progress\n")
		color.Unset()
		os.Exit(1)
	}
	if r.Positives > 0 { // Malware detected
		if !*jsonHash {
			color.Set(color.FgHiRed, color.Bold)
			fmt.Printf("\nGiven hash is KNOWN by VirusTotal and has positive results [%d/%d]\n", r.Positives, r.Total)
			color.Unset()
		}
		printFileResult(r)
	} else { // Malware undetected
		color.Set(color.FgHiGreen, color.Bold)
		fmt.Printf("\nGiven hash is KNOWN by VirusTotal and has no positive results\n")
		color.Unset()
	}
	if !*jsonHash {
		fmt.Printf("Direct link: %s\n\n", r.Permalink)
	}
}
