package reflectedscanner

import (
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/michael1026/paramfinder/types/scan"
	"github.com/michael1026/paramfinder/util"
)

func PrepareScan(canary string, doc *goquery.Document, reflectedScan *scan.ReflectedScan) {
	canaryCount := countReflections(doc, canary)
	reflectedScan.CanaryCount = canaryCount
	reflectedScan.Stable = true
}

func CheckStability(canary *string, doc *goquery.Document, reflectedScan *scan.ReflectedScan) {
	canaryCount := countReflections(doc, *canary)

	if reflectedScan.CanaryCount != canaryCount {
		reflectedScan.Stable = false
	}
}

func CheckDocForReflections(doc *goquery.Document, requestedUrl string, urlInfo *scan.URLInfo) {
	var foundParameters []string
	for param, value := range urlInfo.PotentialParameters {
		if countReflections(doc, value) > urlInfo.ReflectedScan.CanaryCount {
			foundParameters = util.AppendIfMissing(foundParameters, param)
		}
	}
	urlInfo.ReflectedScan.FoundParameters = foundParameters
}

func countReflections(doc *goquery.Document, canary string) int {
	html, err := doc.Html()

	if err != nil {
		fmt.Printf("Error converting to HTML: %s\n", err)
	}

	return strings.Count(html, canary)
}
