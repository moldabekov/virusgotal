package main

import (
	"fmt"
	"os"
	"github.com/moldabekov/virusgotal/vt"
	"github.com/fatih/color"
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
	} else {
		if r.Positives > 0 {
			color.Set(color.FgHiRed)
			fmt.Printf("\nGiven hash [%d/%d] is KNOWN by VirusTotal and has positive results\n", r.Positives, r.Total)
			color.Unset()
		} else {
			color.Set(color.FgHiGreen)
			fmt.Printf("\nGiven hash is KNOWN by VirusTotal and has no positive results\n", r.Positives, r.Total)
			color.Unset()
		}
		fmt.Printf("Direct link: %s\n\n", r.Permalink)
	}
}