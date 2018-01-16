package main

import (
	"github.com/moldabekov/virusgotal/vt"
	"github.com/fatih/color"
	"fmt"
	"os"
)

func printUrlResult(result *govt.UrlReport) {
	color.Set(color.FgHiYellow)
	fmt.Printf("%s scan results:\n\n", *urlname)
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
	os.Exit(0)
}

func scanUrl(urlname string) {
	// Init VT
	apikey := os.Getenv("VT_API_KEY")
	vt, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// Check database
	if !*forceUrl {
		r, err := vt.GetUrlReport(urlname)
		check(err)

		// If file was previously scanned print results
		if r.Status.ResponseCode != 0 {
			printUrlResult(r)
		}
	}

	// Scan URL
	if !*waitUrl {
		report, err := vt.ScanUrl(urlname)
		check(err)
		color.Set(color.FgHiGreen, color.Bold)
		fmt.Printf("Your URL was submitted and scan was queued. Here are details:\n")
		color.Set(color.Reset, color.FgHiCyan)
		fmt.Printf("Link: %s\n", report.Url)
		fmt.Printf("Direct link to scan: %s\n", report.Permalink)
		color.Unset()
	} else { // Wait for results if user wishes
		for m := 0; m <= 10; m++ {
			loader(fmt.Sprintf("waiting for results for %d minutes", m))
			r, err := vt.GetUrlReport(urlname)
			check(err)
			if r.Status.ResponseCode != 0 {
				printUrlResult(r)
			}
		}
		color.Set(color.FgHiRed)
		fmt.Printf("\nSomething went wrong with VirusTotal. Maybe their servers are overloaded.\n" +
			"Please try again later\n")
	}
}
