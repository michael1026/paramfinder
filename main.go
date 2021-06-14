package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

type ArjunResult struct {
	Params []string `json:"params"`
}

type ArjunResults map[string]ArjunResult

var letters = []rune("abcdefghijklmnopqrstuvwxyz")

func main() {
	wg := &sync.WaitGroup{}
	client := buildHttpClient()
	results := ArjunResults{}
	outputFile := flag.String("o", "", "File to output results to (.json)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	var wordlist []string
	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
	}

	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		wg.Add(1)
		time.Sleep(100 * time.Millisecond)
		go findParameters(s.Text(), &wordlist, client, wg, &results)
	}

	wg.Wait()

	resultJson, err := json.Marshal(results)

	if err != nil {
		fmt.Printf("Error marsheling json: %s\n", err)
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

func findParameters(rawUrl string, wordlist *[]string, client *http.Client, wg *sync.WaitGroup, results *ArjunResults) {
	defer wg.Done()

	canary := "wrtqva"
	originalTestUrl, err := url.Parse(rawUrl)

	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
	}

	query := originalTestUrl.Query()
	query.Set(randSeq(4), canary)
	originalTestUrl.RawQuery = query.Encode()

	doc, err := getDocFromURL(originalTestUrl.String(), client)

	if err == nil && doc != nil {
		canaryCount := countReflections(doc, canary)
		potentialParameters := findPotentialParameters(doc, wordlist)
		confirmParameters(client, rawUrl, potentialParameters, canaryCount, results)
	} else if err != nil {
		fmt.Printf("error with doc: %s\n", err)
	}
}

func getDocFromURL(rawUrl string, client *http.Client) (*goquery.Document, error) {
	req, err := http.NewRequest("GET", rawUrl, nil)
	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return nil, err
	}
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error executing request: %s\n", err)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && len(resp.Header.Get("content-type")) >= 9 && resp.Header.Get("content-type")[:9] == "text/html" {
		doc, err := goquery.NewDocumentFromReader(resp.Body)

		if err != nil {
			fmt.Printf("Error reading doc: %s\n", err)
			return nil, err
		}

		return doc, nil
	}

	return nil, nil
}

func confirmParameters(client *http.Client, rawUrl string, potentialParameters *map[string]string, canaryCount int, results *ArjunResults) {
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

	queryStrings := splitParametersIntoQueryStrings(rawUrl, potentialParameters)

	for _, parsedUrl := range queryStrings {
		doc, err := getDocFromURL(parsedUrl.String(), client)

		if err == nil && doc != nil {
			found := checkDocForReflections(doc, potentialParameters, canaryCount)
			if len(found) > 0 {
				oldFinds := (*results)[rawUrl]
				found = append(oldFinds.Params, found...)
				(*results)[rawUrl] = ArjunResult{Params: found}
			}
		}
	}
}

func checkDocForReflections(doc *goquery.Document, potentialParameters *map[string]string, canaryCount int) []string {
	var foundParameters []string
	for param, value := range *potentialParameters {
		if countReflections(doc, value) > canaryCount {
			foundParameters = appendIfMissing(foundParameters, param)
		}
	}
	return foundParameters
}

func countReflections(doc *goquery.Document, canary string) int {
	html, err := doc.Html()

	if err != nil {
		fmt.Printf("Error converting to HTML: %s\n", err)
	}

	return strings.Count(html, canary)
}

func splitParametersIntoQueryStrings(rawUrl string, parameters *map[string]string) (urls []url.URL) {
	size := 40
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

func findPotentialParameters(doc *goquery.Document, wordlist *[]string) *map[string]string {
	parameters := make(map[string]string)
	canary := "wrtqva"
	doc.Find("input").Each(func(index int, item *goquery.Selection) {
		name, ok := item.Attr("name")
		if ok && len(name) > 0 && len(name) < 12 {
			parameters[name] = canary + randSeq(5)
		}
	})

	wordlist = keywordsFromRegex(doc, wordlist)

	for _, word := range *wordlist {
		parameters[word] = canary + randSeq(5)
	}

	return &parameters
}

func buildHttpClient() (c *http.Client) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		fmt.Printf("Error initializing dialer: %s\n", err)
		return
	}

	transport := &http.Transport{
		MaxIdleConns:      -1,
		IdleConnTimeout:   time.Second,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       dialer.Dial,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: re,
		Timeout:       time.Second * 10,
	}

	return client
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

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

			newWordlist = appendIfMissing(*wordlist, match)
		}
	}

	return &newWordlist
}

func appendIfMissing(slice []string, s string) []string {
	for _, ele := range slice {
		if ele == s {
			return slice
		}
	}
	return append(slice, s)
}
