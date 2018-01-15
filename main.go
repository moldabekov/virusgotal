package main

import (
	"encoding/json"
	"fmt"
	"github.com/moldabekov/termux-virustotal/vt"
	"gopkg.in/alecthomas/kingpin.v2"
	"io"
	"os"
	"crypto/sha256"
)

const apiurl = "https://www.virustotal.com/vtapi/v2/"

var (
	app = kingpin.New("virusgotal", "A CLI VirusTotal client built with Go")

	filescan = app.Command("filescan", "File scan mode")
	filename = filescan.Arg("FILE", "File to scan").Required().String()
	force    = filescan.Flag("force check", "").Bool()

	urlscan = app.Command("urlscan", "URL scan mode")
	urlname = urlscan.Arg("URL", "URL to scan").Required().String()
)

func check(err error) {
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
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

func scanFile(filename string) {
	// Init VT
	apikey := os.Getenv("VT_API_KEY")
	vt, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// Check database
	r, err := vt.GetFileReport(sha256sum(filename))
	check(err)

	if r.Status.ResponseCode != 0 {
		result, err := json.MarshalIndent(r, "", "		")
		check(err)

		fmt.Printf("File was already scanned: %s\n", result)
		os.Exit(0)
	}

	// Scan file
	report, err := vt.ScanFile(filename)
	check(err)

	// Unmarshal JSON
	result, err := json.MarshalIndent(report, "", "    ")
	check(err)
	// Print result
	fmt.Printf("File scan result: ")
	os.Stdout.Write(result)
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case filescan.FullCommand():
		scanFile(*filename)
	case urlscan.FullCommand():
		fmt.Printf("URL scan mode: %s\n", *urlname)
	}
}
