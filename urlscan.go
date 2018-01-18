package main

import (
	"github.com/moldabekov/virusgotal/vt"
	"github.com/fatih/color"
	"fmt"
	"os"
)

func printUrlResult(result *govt.UrlReport) {
	color.Set(color.FgHiYellow)
	fmt.Printf("%s scan results:\n", *urlname)
	if !*waitUrl {
		fmt.Printf("VirusTotal link: %s\n\n", result.Permalink)
	}
	color.Set(color.FgHiCyan)
	fmt.Printf("Detection ratio: %v/%v\n\n", result.Positives, result.Total)
	for i := range result.Scans {
		if result.Scans[i].Detected {
			color.Set(color.FgHiRed, color.Bold)
			fmt.Printf("AV: %s\nResult: %s\n\n", i, result.Scans[i].Result)
		} else {
			color.Set(color.FgHiGreen, color.Bold)
			fmt.Printf("AV: %s\nDetected: %t\n\n", i, result.Scans[i].Detected)
		}
	}
	color.Unset()
	os.Exit(0)
}

func scanUrl(urlname string) {
	// Init VT
	apikey := os.Getenv("VT_API_KEY")
	vt, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// Check previous results
	if !*forceUrl {
		r, err := vt.GetUrlReport(urlname)
		check(err)

		// If file was previously scanned print results
		switch r.Status.ResponseCode {
		case 1: // Results exist
			printUrlResult(r)
		case -2: // Scan in progress
			color.Set(color.FgHiRed)
			fmt.Printf("You scan is still in progress\n")
			color.Unset()
			os.Exit(1)
		}
	}

	// Scan URL
	//if !*waitUrl {
	report, err := vt.ScanUrl(urlname)
	check(err)
	color.Set(color.FgHiGreen, color.Bold)
	fmt.Printf("Your URL was submitted and scan was queued. Here are details:\n\n")
	color.Set(color.Reset, color.FgHiCyan)
	fmt.Printf("Link: %s\n", report.Url)
	fmt.Printf("VirusTotal link: %s\n\n", report.Permalink)
	color.Unset()
	if *waitUrl { // Wait for results if user wishes
		for m := 0; m <= 600; m += 30 {
			loader(fmt.Sprintf("waiting for results for %d seconds", m))
			r, err := vt.GetUrlReport(urlname)
			check(err)
			if r.Status.ResponseCode == 1 {
				fmt.Printf("scan took ~ %d seconds\n", m)
				printUrlResult(r)
			}
		}
		color.Set(color.FgHiRed)
		fmt.Printf("\nSomething went wrong with VirusTotal. Maybe their servers are overloaded.\n" +
			"Please try again later\n")
	}
}
