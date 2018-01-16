package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/moldabekov/termux-virustotal/vt"
	"github.com/moldabekov/spinner"
	"gopkg.in/alecthomas/kingpin.v2"
)

const apiurl = "https://www.virustotal.com/vtapi/v2/"

var (
	app = kingpin.New("virusgotal", "A CLI VirusTotal client built with Go")

	filescan  = app.Command("file", "File scan mode")
	filename  = filescan.Arg("FILE", "File to scan").Required().String()
	forceFile = filescan.Flag("force", "rescan file").Bool()
	waitFile  = filescan.Flag("wait", "wait for results").Bool()

	urlscan  = app.Command("url", "URL scan mode")
	urlname  = urlscan.Arg("URL", "URL to scan").Required().String()
	forceUrl = urlscan.Flag("force", "rescan URL").Bool()
	waitUrl  = urlscan.Flag("wait", "wait for results").Bool()
)

func check(err error) {
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
}

func loader(s string) {
	spin := spinner.New("%s " + s)
	spin.Start()
	defer spin.Stop()
	time.Sleep(60 * time.Second)
}

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
	color.Set(color.FgHiYellow)
	fmt.Printf("%s file scan results:\n", *filename)
	fmt.Printf("sha256 hashsum: %s\n\n", result.Sha256)
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

func scanFile(filename string) {
	// Init VT
	apikey := os.Getenv("VT_API_KEY")
	vt, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// Check database
	if !*forceFile {
		r, err := vt.GetFileReport(sha256sum(filename))
		check(err)

		// If file was previously scanned print results
		if r.Status.ResponseCode != 0 {
			printFileResult(r)
		}
	}

	// Scan file
	if !*waitFile {
		report, err := vt.ScanFile(filename)
		check(err)
		fmt.Printf("%s\n", report.Status.VerboseMsg)
	} else { // Wait for results if user wishes
		for m := 0; m <= 10; m++ {
			loader(fmt.Sprintf("waiting for results for %d minutes", m))
			r, err := vt.GetFileReport(sha256sum(filename))
			check(err)
			if r.Status.ResponseCode != 0 {
				printFileResult(r)
			}
		}
		fmt.Printf("\nSomething went wrong with VirusTotal. Maybe their servers are overloaded.\n" +
			" Please try again later\n")
	}
}

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
		fmt.Printf("%s\n", report.Status.VerboseMsg)
	} else { // Wait for results if user wishes
		for m:=0; m<=10; m++ {
			loader(fmt.Sprintf("waiting for results for %d minutes", m))
			r, err := vt.GetUrlReport(urlname)
			check(err)
			if r.Status.ResponseCode != 0 {
				printUrlResult(r)
			}
		}
		fmt.Printf("\nSomething went wrong with VirusTotal. Maybe their servers are overloaded.\n" +
			" Please try again later\n")
	}
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case filescan.FullCommand():
		scanFile(*filename)
	case urlscan.FullCommand():
		scanUrl(*urlname)
	}
}
