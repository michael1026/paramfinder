package main

import (
	"bufio"
	"encoding/json"
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
* Break into different detection types (reflected, extra headers, number of each tag, etc) - Reflected done
* Check stability of each detection type for each URL - Done
* Ability to disable certain checks
* Check max URL length for each host
/***************************************/

func main() {
	var wordlist []string
	wg := &sync.WaitGroup{}
	scanInfo := scan.Scan{}

	outputFile := flag.String("o", "", "File to output results to (.json)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	cookieFile := flag.String("C", "", "File containing cookie")
	threads := flag.Int("t", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
		scanInfo.WordList = wordlist
	}

	jar := sessionManager.ReadCookieJson(*cookieFile)
	client := scanhttp.BuildHttpClient(jar)
	scanInfo.ScanResults = make(scan.ScanResults)
	scanInfo.JsonResults = make(scan.JsonResults)
	urls := make(chan string)

	s := bufio.NewScanner(os.Stdin)

	for i := 0; i < *threads; i++ {
		wg.Add(1)

		go findParameters(urls, &wordlist, client, wg, &scanInfo)
	}

	for s.Scan() {
		urls <- s.Text()
	}

	close(urls)

	wg.Wait()

	resultJson, err := json.Marshal(scanInfo.JsonResults)

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

func findParameters(urls chan string, wordlist *[]string, client *http.Client, wg *sync.WaitGroup, scanInfo *scan.Scan) {
	defer wg.Done()

	canary := "wrtqva"

	for rawUrl := range urls {
		scanInfo.ScanResults[rawUrl] = &scan.URLInfo{}
		scanInfo.JsonResults[rawUrl] = scan.JsonResult{}

		urlInfo := scanInfo.ScanResults[rawUrl]
		urlInfo.ReflectedScan = &scan.ReflectedScan{}

		for i := 0; i < 5; i++ {
			originalTestUrl, err := url.Parse(rawUrl)

			if err != nil {
				fmt.Printf("Error parsing URL: %s\n", err)
			}

			query := originalTestUrl.Query()
			query.Set(util.RandSeq(4), canary)
			originalTestUrl.RawQuery = query.Encode()

			doc, err := scanhttp.GetDocFromURL(originalTestUrl.String(), client)

			if err == nil && doc != nil {
				if i == 0 {
					reflectedscanner.PrepareScan(canary, doc, urlInfo.ReflectedScan)
					urlInfo.PotentialParameters = findPotentialParameters(doc, wordlist)
				} else if urlInfo.ReflectedScan.Stable {
					reflectedscanner.CheckStability(&canary, doc, urlInfo.ReflectedScan)
				}
			}
		}
		confirmParameters(client, rawUrl, scanInfo)
	}
}

/**********************************************************************************
*
* Make requests, then check page responses to determine if params affected the page
*
***********************************************************************************/

func confirmParameters(client *http.Client, rawUrl string, scanInfo *scan.Scan) {
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

	defer resp.Body.Close()

	queryStrings := splitParametersIntoQueryStrings(rawUrl, &scanInfo.ScanResults[rawUrl].PotentialParameters)

	for _, parsedUrl := range queryStrings {
		if scanInfo.ScanResults[rawUrl].ReflectedScan.Stable == false {
			fmt.Printf("URL %s is unstable. Skipping\n", rawUrl)
			continue
		}

		doc, err := scanhttp.GetDocFromURL(parsedUrl.String(), client)

		if err != nil {
			fmt.Printf("Error creating document %s\n", err)
			continue
		}

		if doc != nil {
			reflectedscanner.CheckDocForReflections(doc, rawUrl, scanInfo.ScanResults[rawUrl])

			found := scanInfo.ScanResults[rawUrl].ReflectedScan.FoundParameters

			if len(found) > 0 {
				oldFinds := (scanInfo.JsonResults)[rawUrl]
				found = append(oldFinds.Params, found...)
				scanInfo.JsonResults[rawUrl] = scan.JsonResult{Params: found}
			}
		}
	}
}

/************************************************************************
*
* Splits parameter list into multiple query strings based on size
*
*************************************************************************/

func splitParametersIntoQueryStrings(rawUrl string, parameters *map[string]string) (urls []url.URL) {
	size := 80
	i := 0
	parsedUrl, err := url.Parse(rawUrl)

	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
		return
	}

	urlWithQuery, err := url.Parse(rawUrl)

	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
		return
	}

	query := parsedUrl.Query()

	for name, value := range *parameters {
		if i == size {
			i = 0
			urlWithQuery.RawQuery = query.Encode()
			urls = append(urls, *urlWithQuery)
			query = parsedUrl.Query()
		}
		query.Set(name, value)
		i++
	}

	urlWithQuery.RawQuery = query.Encode()
	urls = append(urls, *urlWithQuery)

	return urls
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
		if ok && len(name) > 0 && len(name) < 12 {
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

func calculateMaxParameters()
