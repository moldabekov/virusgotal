package main

import (
	"os"
	"crypto/sha256"
	"io"
	"fmt"
	"github.com/moldabekov/virusgotal/vt"
	"github.com/fatih/color"
	"encoding/json"
)

func sha256sum(filename string) string {
	f, err := os.Open(filename)
	check(err)
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}

	return fmt.Sprintf("%x\n", h.Sum(nil))
}

func printFileResult(result *govt.FileReport) {
	if (!*jsonFile) && (!*jsonHash) {
		color.Set(color.FgHiYellow)
		if len(*filename) > 0 {
			fmt.Printf("%s file scan results:\n", *filename)
		}
		if !*waitFile {
			fmt.Printf("sha256 hashsum: %s\n", result.Sha256)
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
	} else {
		j, err := json.MarshalIndent(result, "", "  ")
		check(err)
		os.Stdout.Write(j)
		os.Exit(0)
	}
}

func scanFile(filename string) {
	// Init VT
	apikey := os.Getenv("VT_API_KEY")
	vt, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// Check previous results
	if !*forceFile {
		r, err := vt.GetFileReport(sha256sum(filename))
		check(err)

		// If file was previously scanned print results
		switch r.Status.ResponseCode {
		case 1: // Results exist
			printFileResult(r)
		case -2: // Scan in progress
			color.Set(color.FgHiRed)
			fmt.Printf("You scan is still in progress\n")
			color.Unset()
			os.Exit(1)
		}
	}

	// Scan file
	report, err := vt.ScanFile(filename)
	check(err)
	color.Set(color.FgHiGreen, color.Bold)
	if !*jsonFile && !*jsonHash {
		fmt.Printf("Your file was submitted and scan was queued. Here are details:\n\n")
		color.Set(color.Reset, color.FgHiCyan)
		fmt.Printf("sha256 hash: %s\n", report.Sha256)
		fmt.Printf("VirusTotal link: %s\n\n", report.Permalink)
		color.Unset()
	}
	if *waitFile { // Wait for results if user wishes
		for m := 0; m <= 600; m += 30 { // m == minutes
			loader(fmt.Sprintf("waiting for results for %d seconds", m))
			r, err := vt.GetFileReport(sha256sum(filename))
			check(err)
			if r.Status.ResponseCode == 1 {
				if !*jsonFile && !*jsonHash {
					fmt.Printf("scan took ~ %d seconds\n", m)
				}
				printFileResult(r)
			}
		}
		color.Set(color.FgHiRed)
		fmt.Printf("\nSomething went wrong with VirusTotal. Maybe their servers are overloaded.\n" +
			"Please try again later\n")
	}
}
