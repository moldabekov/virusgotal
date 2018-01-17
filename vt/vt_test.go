/*
A few test cases for the `govt` package.

We cannot have many test cases, because the public API is limited to four requests per minute.
So here, we demonstrate that the scheme works, and leave it at that

Written by Willi Ballenthin while at Mandiant.
June, 2013.
*/
package govt

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"time"
)

var runExpensive bool
var runPrivate bool
var apikey string

func init() {
	flag.StringVar(&apikey, "apikey", "", "VT api key used for testing")
	flag.BoolVar(&runExpensive, "run-expensive", false, "Flag to run expensive tests")
	flag.BoolVar(&runPrivate, "run-private", false, "Flag to run private API tests")
	flag.Parse()
	if apikey == "" {
		fmt.Println("API key is required to run the tests agains VT")
		os.Exit(1)
	}
}

// TestGetFileReport tests the structure and execution of a request.
func TestGetFileReport(t *testing.T) {
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}
	var testMd5 = "eeb024f2c81f0d55936fb825d21a91d6"
	report, err := govt.GetFileReport(testMd5)

	if err != nil {
		t.Error("Error requesting report: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}

	if report.Md5 != testMd5 {
		t.Error("Requested MD5 does not match result: ", testMd5, " vs. ", report.Md5)
		return
	}
}

// TestGetDetailedFileReport tests the structure and execution of a request.
func TestGetDetailedFileReport(t *testing.T) {
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	var testMd5 = "e320908e9cac93876be08549bf0be67f"
	var testFpr = []string{
		"9617094A1CFB59AE7C1F7DFDB6739E4E7C40508F", // Microsoft Corporation
		"3036E3B25B88A55B86FC90E6E9EAAD5081445166", // Microsoft Code Signing PCA
		"A43489159A520F0D93D032CCAF37E7FE20A8B419", // Microsoft Root Authority
	}

	report, err := govt.GetDetailedFileReport(testMd5)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}

	if report.Md5 != testMd5 {
		t.Error("Requested MD5 does not match result: ", testMd5, " vs. ", report.Md5)
		return
	}

	i := 0
	for _, sig := range report.AdditionnalInfo.Signature.SignersDetails {
		fpr := sig.Thumbprint
		if fpr != testFpr[i] {
			t.Error("Requested signature fingerprint does not match result: ", testFpr[i], " vs. ", fpr)
			return
		}
		i++
	}
}

// TestGetFileReports tests the structure and execution of a request.
func TestGetFileReports(t *testing.T) {
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	md5s := []string{"eeb024f2c81f0d55936fb825d21a91d6", "1F4C43ADFD45381CFDAD1FAFEA16B808"}
	reports, err := govt.GetFileReports(md5s)
	if err != nil {
		t.Error("Error requesting reports: ", err.Error())
		return
	}

	for _, r := range *reports {
		if r.ResponseCode != 1 {
			t.Errorf("Response code indicates failure: %d", r.ResponseCode)
			return
		}
	}
}

// TestRescanFile tests the structure and execution of a request.
func TestRescanFile(t *testing.T) {
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}
	var testMd5 = "eeb024f2c81f0d55936fb825d21a91d6"
	report, err := govt.RescanFile(testMd5)
	if err != nil {
		t.Error("Error requesting rescan: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}
}

// Private API calls

// TestFileFeed tests the new files feed private API
func TestFileFeed(t *testing.T) {
	if !runPrivate {
		t.Skip("To run this test, use: go test -run-private")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	// Current time in UTC minus one hour
	var packageRange = time.Now().UTC().Add(time.Duration(-1 * time.Hour)).Format("20060102T1504")

	_, err = govt.GetFileFeed(packageRange)
	if err != nil {
		t.Error("Error requesting feed: ", err.Error())
	}
}

// Expensive from here

// TestRescanFiles tests the structure and execution of a request.
func TestRescanFiles(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	testMd5s := []string{"eeb024f2c81f0d55936fb825d21a91d6", "eeb024f2c81f0d55936fb825d21a91d6"}
	reports, err := govt.RescanFiles(testMd5s)
	if err != nil {
		t.Error("Error requesting rescan: ", err.Error())
		return
	}
	for _, report := range *reports {
		if report.ResponseCode != 1 {
			t.Errorf("Response code indicates failure: %d", report.ResponseCode)
			return
		}
	}
}

// TestScanUrl tests the structure and execution of a request.
func TestScanUrl(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	var testURL = "http://www.virustotal.com/"
	report, err := govt.ScanUrl(testURL)
	if err != nil {
		t.Error("Error requesting Scan: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}
}

// TestScanUrls tests the structure and execution of a request.
func TestScanUrls(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	testURLs := []string{"http://www.virustotal.com", "http://www.google.com"}
	reports, err := govt.ScanUrls(testURLs)
	if err != nil {
		t.Error("Error requesting scan: ", err.Error())
		return
	}
	for _, report := range *reports {
		if report.ResponseCode != 1 {
			t.Errorf("Response code indicates failure: %d", report.ResponseCode)
			return
		}
	}
}

// TestGetUrlReport tests the structure and execution of a request.
func TestGetUrlReport(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	var testURL = "http://www.virustotal.com/"
	report, err := govt.GetUrlReport(testURL)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}

	if report.Url != testURL {
		t.Error("Requested URL does not match result: ", testURL, " vs. ", report.Url)
		return
	}
}

// TestGetUrlReports tests the structure and execution of a request.
func TestGetUrlReports(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}
	var testURLs = []string{"http://www.virustotal.com", "http://www.google.com"}
	reports, err := govt.GetUrlReports(testURLs)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
		return
	}
	for _, report := range *reports {
		if report.ResponseCode != 1 {
			t.Errorf("Response code indicates failure: %d", report.ResponseCode)
			return
		}
	}
}

// TestGetIpReport tests the structure and execution of a request.
//   It does not perform logical tests on the returned data.
func TestGetIpReport(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	var testIP = "8.8.8.8"
	report, err := govt.GetIpReport(testIP)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}
}

// TestGetDomainReport tests the structure and execution of a request.
//   It does not perform logical tests on the returned data.
func TestGetDomainReport(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	var testDomain = "www.virustotal.com"
	report, err := govt.GetDomainReport(testDomain)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}
}

// TestGetComments tests the structure and execution of a request.
func TestGetComments(t *testing.T) {
	if !runExpensive {
		t.Skip("To run this test, use: go test -run-expensive")
	}
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	testSHA256 := "2fcc9209ddeb18b2dbd4db5f42dd477feaf4a1c3028eb6393dbaa21bd26b800c"
	report, err := govt.GetComments(testSHA256)
	if err != nil {
		t.Error("Error requesting comments: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Errorf("Response code indicates failure: %d", report.ResponseCode)
		return
	}
}
