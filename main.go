package main

import (
	"os"
	"gopkg.in/alecthomas/kingpin.v2"
)

const apiurl = "https://www.virustotal.com/vtapi/v2/"

var (
	app = kingpin.New("virusgotal", "A CLI VirusTotal client built with Go")

	filescan  = app.Command("file", "File scanning mode")
	filename  = filescan.Arg("FILE", "File to scan").Required().String()
	forceFile = filescan.Flag("force", "rescan file").Bool()
	waitFile  = filescan.Flag("wait", "wait for results").Bool()
	jsonFile = filescan.Flag("json","export results to JSON").Bool()

	urlscan  = app.Command("url", "URL scanning mode")
	urlname  = urlscan.Arg("URL", "URL to scan").Required().String()
	forceUrl = urlscan.Flag("force", "rescan URL").Bool()
	waitUrl  = urlscan.Flag("wait", "wait for results").Bool()
	jsonUrl = urlscan.Flag("json","export results to JSON").Bool()

	hashscan = app.Command("hash", "Search files by hash")
	hash     = hashscan.Arg("HASH", "SHA1/SHA256/MD5 hash").Required().String()
	jsonHash = hashscan.Flag("json","export results to JSON").Bool()
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case filescan.FullCommand():
		scanFile(*filename)
	case urlscan.FullCommand():
		scanUrl(*urlname)
	case hashscan.FullCommand():
		searchHash(*hash)
	}
}
