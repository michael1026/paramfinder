package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/michael1026/paramfinder/reflectedscanner"
	"github.com/michael1026/paramfinder/scanhttp"
	"github.com/michael1026/paramfinder/types/scan"
	"github.com/michael1026/paramfinder/util"

	"github.com/PuerkitoBio/goquery"
	"github.com/michael1026/sessionManager"
)

/***************************************
* Ideas....
* Break into different detection types (reflected, extra headers, number of each tag, etc)
* - Reflected done
* Check stability of each detection type for each URL - Done
* Ability to disable certain checks
* Check max URL length for each host - Done
* Write JSON as program runs
/***************************************/

func main() {
	var wordlist []string
	wg := &sync.WaitGroup{}
	scanInfo := scan.Scan{}
	scanInfo.FillDefaults()

	outputFile := flag.String("o", "", "File to output results to (.json)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	cookieFile := flag.String("C", "", "File containing cookie")
	threads := flag.Int("t", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")
	url := flag.String("u", "", "Single URL to scan")

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
		scanInfo.WordList = wordlist
	}

	jar := sessionManager.ReadCookieJson(*cookieFile)
	client := scanhttp.BuildHttpClient(jar)
	urls := make(chan string)

	s := bufio.NewScanner(os.Stdin)

	for i := 0; i < *threads; i++ {
		wg.Add(1)

		go findParameters(urls, client, wg, &scanInfo)
	}

	if *url != "" {
		scanInfo.ScanResults[*url] = &scan.URLInfo{}
		urls <- *url
	}

	for s.Scan() {
		scanInfo.ScanResults[s.Text()] = &scan.URLInfo{}
		urls <- s.Text()
	}

	close(urls)

	wg.Wait()

	resultJson, err := util.JSONMarshal(scanInfo.JsonResults)

	if err != nil {
		log.Fatalf("Error marsheling json: %s\n", err)
	}

	err = ioutil.WriteFile(*outputFile, resultJson, 0644)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func readWordlistIntoFile(wordlistPath string) ([]string, error) {
	lines, err := readLines(wordlistPath)
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}
	return lines, err
}

func findParameters(urls chan string, client *http.Client, wg *sync.WaitGroup, scanInfo *scan.Scan) {
	defer wg.Done()

	canary := "wrtqva"
	scanInfo.CanaryValue = util.RandSeq(6)

	for rawUrl := range urls {
		urlInfo := scanInfo.ScanResults[rawUrl]
		urlInfo.ReflectedScan = &scan.ReflectedScan{}

		for i := 0; i < 5; i++ {
			originalTestUrl, err := url.Parse(rawUrl)

			if err != nil {
				fmt.Printf("Error parsing URL: %s\n", err)
			}

			query := originalTestUrl.Query()
			query.Set(util.RandSeq(6), canary)
			originalTestUrl.RawQuery = query.Encode()

			doc, err := scanhttp.GetDocFromURL(originalTestUrl.String(), client)

			if err == nil && doc != nil {
				if i == 0 {
					reflectedscanner.PrepareScan(canary, doc, urlInfo.ReflectedScan)
					urlInfo.PotentialParameters = findPotentialParameters(doc, &scanInfo.WordList)
				} else if urlInfo.ReflectedScan.Stable {
					reflectedscanner.CheckStability(&canary, doc, urlInfo.ReflectedScan)
				}
			}
		}
		calculateMaxParameters(scanInfo.ScanResults[rawUrl], client, rawUrl)
		results := confirmParameters(client, rawUrl, scanInfo)

		if len(results) > 0 {
			oldFinds := (scanInfo.JsonResults)[rawUrl]
			results = append(oldFinds.Params, results...)
			scanInfo.JsonResults[rawUrl] = scan.JsonResult{Params: results}
		}
	}
}

/**********************************************************************************
*
* Make requests, then check page responses to determine if params affected the page
*
***********************************************************************************/

func confirmParameters(client *http.Client, rawUrl string, scanInfo *scan.Scan) []string {
	req, err := http.NewRequest("GET", rawUrl, nil)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return []string{}
	}
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error executing request: %s\n", err)
		return []string{}
	}

	foundParams := []string{}

	defer resp.Body.Close()

	queryStrings :=
		splitParametersIntoMaxSize(
			rawUrl,
			&scanInfo.ScanResults[rawUrl].PotentialParameters,
			scanInfo.ScanResults[rawUrl].MaxParams,
			scanInfo.CanaryValue)

	for _, paramValues := range queryStrings {
		if scanInfo.ScanResults[rawUrl].ReflectedScan.Stable == false {
			fmt.Printf("URL %s is unstable. Skipping\n", rawUrl)
			continue
		}

		parsedUrl, err := url.Parse(rawUrl)

		if err != nil {
			continue
		}

		query := parsedUrl.Query()

		for param, value := range paramValues {
			query.Add(param, value)
		}

		parsedUrl.RawQuery = query.Encode()

		doc, err := scanhttp.GetDocFromURL(parsedUrl.String(), client)

		if err != nil {
			fmt.Printf("Error creating document %s\n", err)
			continue
		}

		if doc != nil {
			pageDifferent := reflectedscanner.CheckDocForReflections(doc, scanInfo.ScanResults[rawUrl], scanInfo, paramValues, rawUrl)

			if pageDifferent {
				util.DeleteByKey(&paramValues, scanInfo.CanaryValue)
				if len(paramValues) == 1 {
					for param := range paramValues {
						found := scanInfo.ScanResults[rawUrl].ReflectedScan.FoundParameters
						oldFinds := (scanInfo.JsonResults)[rawUrl]
						found = append(oldFinds.Params, param)
						scanInfo.JsonResults[rawUrl] = scan.JsonResult{Params: found}
						return []string{param}
					}
				}

				extraParams := splitAndScan(paramValues, scanInfo, rawUrl, client)
				foundParams = append(foundParams, extraParams...)
			}

			found := scanInfo.ScanResults[rawUrl].ReflectedScan.FoundParameters
			foundParams = append(found, foundParams...)
		}
	}

	return foundParams
}

func splitAndScan(paramValues map[string]string, scanInfo *scan.Scan, rawUrl string, client *http.Client) (foundParams []string) {
	split1, split2 := util.SplitMap(paramValues)
	splits := []map[string]string{split1, split2}

	for _, split := range splits {
		newScan := scan.Scan{}
		newScan.FillDefaults()
		newScan.CanaryValue = scanInfo.CanaryValue
		newScan.ScanResults[rawUrl] = &scan.URLInfo{}
		newScan.ScanResults[rawUrl].ReflectedScan = &scan.ReflectedScan{}
		newScan.ScanResults[rawUrl].ReflectedScan.CanaryCount = scanInfo.ScanResults[rawUrl].ReflectedScan.CanaryCount
		newScan.ScanResults[rawUrl].ReflectedScan.Stable = true
		newScan.ScanResults[rawUrl].PotentialParameters = split
		newScan.ScanResults[rawUrl].ReflectedScan.FoundParameters = scanInfo.ScanResults[rawUrl].ReflectedScan.FoundParameters
		params := confirmParameters(client, rawUrl, &newScan)
		if len(params) > 0 {
			for _, param := range params {
				foundParams = append(foundParams, param)
			}
		}
	}

	return foundParams
}

/************************************************************************
*
* Splits parameter list into multiple query strings based on size
*
*************************************************************************/

func splitParametersIntoMaxSize(rawUrl string, parameters *map[string]string, maxParams int, canaryValue string) (splitParameters []map[string]string) {
	i := 0

	paramValues := make(map[string]string)
	paramValues[util.RandSeq(6)] = canaryValue

	for name, value := range *parameters {
		if i == maxParams {
			i = 0
			splitParameters = append(splitParameters, paramValues)
			paramValues = make(map[string]string)
			paramValues[util.RandSeq(6)] = canaryValue
		}
		paramValues[name] = value
		i++
	}

	splitParameters = append(splitParameters, paramValues)

	return splitParameters
}

/***********************************************************************
*
* Used to find possible parameter names by looking at the page source
*
************************************************************************/

func findPotentialParameters(doc *goquery.Document, wordlist *[]string) map[string]string {
	parameters := make(map[string]string)
	canary := "wrtqva"
	doc.Find("input").Each(func(index int, item *goquery.Selection) {
		name, ok := item.Attr("name")

		if ok && len(name) > 0 && len(name) < 20 {
			parameters[name] = canary + util.RandSeq(5)
		}
	})

	wordlist = keywordsFromRegex(doc, wordlist)

	for _, word := range *wordlist {
		parameters[word] = canary + util.RandSeq(5)
	}

	return parameters
}

/***********************************************************************
*
* Finds keywords by using some regex against the page source
*
************************************************************************/

func keywordsFromRegex(doc *goquery.Document, wordlist *[]string) *[]string {
	html, err := doc.Html()
	var newWordlist []string

	if err != nil {
		fmt.Printf("Error reading doc: %s\n", err)
	}

	regexs := [...]string{"\"[a-z_\\-]+\":", "[a-z_\\-]+:(\\d|{|\"|\\s)"}

	for _, regex := range regexs {
		re := regexp.MustCompile(regex)
		matches := re.FindStringSubmatch(html)

		for _, match := range matches {
			match = strings.ReplaceAll(match, "\"", "")
			match = strings.ReplaceAll(match, "{", "")
			match = strings.ReplaceAll(match, ":", "")
			match = strings.ReplaceAll(match, " ", "")

			if match != "" {
				newWordlist = util.AppendIfMissing(*wordlist, match)
			}
		}
	}

	return &newWordlist
}

/***********************************************************************
*
* Calculates the max number of parameters before the page breaks
*
************************************************************************/

func calculateMaxParameters(scanInfo *scan.URLInfo, client *http.Client, rawUrl string) {
	maxParameters := 50
	parsedUrl, err := url.Parse(rawUrl)

	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
		return
	}

	req, err := http.NewRequest("GET", rawUrl, nil)

	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return
	}
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error executing request: %s\n", err)
		return
	}

	resp.Body.Close()

	query := parsedUrl.Query()

	for i := 0; i < 50; i++ {
		query.Set(util.RandSeq(7), util.RandSeq(7))
	}

	for i := 0; i < 30; i++ {
		for i := 0; i < 50; i++ {
			query.Set(util.RandSeq(10), util.RandSeq(10))
		}

		req.URL.RawQuery = query.Encode()

		resp, err = client.Do(req)

		if err != nil || resp.StatusCode != http.StatusOK {
			scanInfo.MaxParams = maxParameters
			return
		}

		maxParameters += 50
	}

	scanInfo.MaxParams = 1500
}
