package main

import (
	"os"
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

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case filescan.FullCommand():
		scanFile(*filename)
	case urlscan.FullCommand():
		scanUrl(*urlname)
	}
}
