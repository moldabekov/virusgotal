<p align="center">
	<a href="#"><img src="https://user-images.githubusercontent.com/669547/35134359-108c002c-fd00-11e7-9539-32e021a22735.png" alt="VirusGotal" width="300"></a>
</p>
<h3 align="center">Scan any file & URL from your terminal!</h3>
<p align="center">virusgotal is a simple CLI client to a famous VirusTotal service. No more hassle with URL and file scans ever.</p>
<p align="center">
	<a href="https://travis-ci.org/moldabekov/virusgotal"><img src="https://img.shields.io/travis/moldabekov/virusgotal.svg?branch=master"></a>
	<a href="https://goreportcard.com/report/github.com/moldabekov/virusgotal"><img src="https://goreportcard.com/badge/github.com/moldabekov/virusgotal?service=github"></a>
	<a href="https://github.com/moldabekov/virusgotal/releases/latest"><img src="https://img.shields.io/github/release/moldabekov/virusgotal.svg"></a>
	<a href="https://github.com/moldabekov/virusgotal/releases/"><img src="https://img.shields.io/github/downloads/moldabekov/virusgotal/total.svg"></a>
	<a href="https://github.com/moldabekov/virusgotal/blob/master/LICENSE"><img src=https://img.shields.io/github/license/moldabekov/virusgotal.svg></a>
</p>
<p align="center">
	<a href="https://github.com/moldabekov/virusgotal/releases"><b>Download</b></a>
	<!--· <a href="https://t.me/">Contact</a-->
</p>

# Virusgotal

Yes, it is yet another wrapper. However it's a crossplatform CLI tool which runs on Linux/macOS/Windows/\*BSD and even on Android.

It's also requires **zero** runtime dependency.


## Installation

**Option 1.** The easiest way is to [grab package](https://github.com/moldabekov/virusgotal/releases) from [Github Releases](https://github.com/moldabekov/virusgotal/releases) page and place it (*preferably*) in your $PATH.
For more convenient usage rename `virusgotal-$OS-$ARCH` to `virusgotal`.

**Option 2.** If you want to build it manually then you are welcome:
```
go get -u github.com/moldabekov/virusgotal
go install -u github.com/moldabekov/virusgotal
```
*NOTE: make sure you have included $GOPATH/bin to $PATH*

You will need VirusTotal API key. You can obtain it from your profile at VT.
After obtaining it export the key to env variable:

`export VT_API_KEY=<your key>`

## Usage

At the moment `virusgotal` supports files/URLs scan and search results by file hash (SHA1/SHA256/MD5).

Syntax:
* To scan a file:
`virusgotal file <FILE>`
  * To rescan a file:
  `virusgotal file <FILE> --force`
  * To wait for file scan results in a loop:
  `virusgotal file <FILE> --wait`
  * To get JSON formatted result:
  `virusgotal file <FILE> --json`

* To scan a URL:
`virusgotal url <URL>`
  * To rescan a URL:
  `virusgotal url <URL> --force`
  * To wait for URL scan results in a loop:
  `virusgotal url <URL> --wait`
  * To get JSON formatted result:
  `virusgotal url <FILE> --json`

* To lookup a file hash in VirusTotal database:
`virusgotal hash <HASH>`
  * Get JSON formatted result:
  `virustotal hash <HASH> --json`

You also can combine options: `virusgotal file --wait --json --force <FILE>`

## Contribution

All kinds of contribution are welcome! Please send your PRs, bug reports, ideas, suggestions.

## License
MIT License
