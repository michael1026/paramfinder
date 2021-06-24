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
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

type CookieInfo map[string]string

type ArjunResult struct {
	Params []string `json:"params"`
}

type ArjunResults map[string]ArjunResult

type HeaderArgs []string

func (h *HeaderArgs) Set(val string) error {
	*h = append(*h, val)
	return nil
}

func (h HeaderArgs) String() string {
	return "string"
}

var letters = []rune("abcdefghijklmnopqrstuvwxyz")

func main() {
	wg := &sync.WaitGroup{}
	results := ArjunResults{}
	outputFile := flag.String("o", "", "File to output results to (.json)")

	wordlistFile := flag.String("w", "", "Wordlist file")

	cookieFile := flag.String("C", "", "File containing cookie")

	threads := flag.Int("t", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")

	var headers HeaderArgs
	flag.Var(&headers, "H", "")
	var wordlist []string

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
	}

	jar := readCookieJson(*cookieFile)
	client := buildHttpClient(jar)
	urls := make(chan string)

	s := bufio.NewScanner(os.Stdin)

	for i := 0; i < *threads; i++ {
		wg.Add(1)

		go findParameters(urls, &wordlist, client, wg, &results, &headers)
	}

	for s.Scan() {
		urls <- s.Text()
	}

	close(urls)

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

func findParameters(urls chan string, wordlist *[]string, client *http.Client, wg *sync.WaitGroup, results *ArjunResults, headers *HeaderArgs) {
	defer wg.Done()

	canary := "wrtqva"

	for rawUrl := range urls {
		originalTestUrl, err := url.Parse(rawUrl)

		if err != nil {
			fmt.Printf("Error parsing URL: %s\n", err)
		}

		query := originalTestUrl.Query()
		query.Set(randSeq(4), canary)
		originalTestUrl.RawQuery = query.Encode()

		doc, err := getDocFromURL(originalTestUrl.String(), client, headers)

		if err == nil && doc != nil {
			canaryCount := countReflections(doc, canary)
			potentialParameters := findPotentialParameters(doc, wordlist)
			confirmParameters(client, rawUrl, potentialParameters, canaryCount, results, headers)
		} else if err != nil {
			fmt.Printf("error with doc: %s\n", err)
		}
	}
}

func getDocFromURL(rawUrl string, client *http.Client, headers *HeaderArgs) (*goquery.Document, error) {
	req, err := http.NewRequest("GET", rawUrl, nil)

	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return nil, err
	}
	req.Header.Set("Connection", "close")

	for _, h := range *headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			continue
		}

		req.Header.Set(parts[0], parts[1])
	}

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

func confirmParameters(client *http.Client, rawUrl string, potentialParameters *map[string]string, canaryCount int, results *ArjunResults, headers *HeaderArgs) {
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
		doc, err := getDocFromURL(parsedUrl.String(), client, headers)

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
	size := 160
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

func buildHttpClient(jar *cookiejar.Jar) (c *http.Client) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return
	}

	transport := &http.Transport{
		MaxIdleConns:      100,
		IdleConnTimeout:   time.Second * 10,
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
		Jar:           jar,
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

			if match != "" {
				newWordlist = appendIfMissing(*wordlist, match)
			}
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

func readCookiesFromString(s string) []*http.Cookie {
	cookieStrings := strings.Split(s, ";")

	for i, c := range cookieStrings {
		cookieStrings[i] = strings.TrimSpace(c)
	}

	cookieCount := len(cookieStrings)
	if cookieCount == 0 {
		return []*http.Cookie{}
	}
	cookies := make([]*http.Cookie, 0, cookieCount)
	for _, line := range cookieStrings {
		parts := strings.Split(strings.TrimSpace(line), ";")
		if len(parts) == 1 && parts[0] == "" {
			continue
		}
		parts[0] = strings.TrimSpace(parts[0])
		j := strings.Index(parts[0], "=")
		if j < 0 {
			continue
		}
		name, value := parts[0][:j], parts[0][j+1:]

		value, ok := parseCookieValue(value, true)
		if !ok {
			continue
		}
		c := &http.Cookie{
			Name:  name,
			Value: value,
			Raw:   line,
		}
		for i := 1; i < len(parts); i++ {
			parts[i] = strings.TrimSpace(parts[i])
			if len(parts[i]) == 0 {
				continue
			}

			attr, val := parts[i], ""
			if j := strings.Index(attr, "="); j >= 0 {
				attr, val = attr[:j], attr[j+1:]
			}
			lowerAttr := strings.ToLower(attr)
			val, ok = parseCookieValue(val, false)
			if !ok {
				c.Unparsed = append(c.Unparsed, parts[i])
				continue
			}
			switch lowerAttr {
			case "secure":
				c.Secure = true
				continue
			case "httponly":
				c.HttpOnly = true
				continue
			case "domain":
				c.Domain = val
				continue
			case "max-age":
				secs, err := strconv.Atoi(val)
				if err != nil || secs != 0 && val[0] == '0' {
					break
				}
				if secs <= 0 {
					secs = -1
				}
				c.MaxAge = secs
				continue
			case "expires":
				c.RawExpires = val
				exptime, err := time.Parse(time.RFC1123, val)
				if err != nil {
					exptime, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", val)
					if err != nil {
						c.Expires = time.Time{}
						break
					}
				}
				c.Expires = exptime.UTC()
				continue
			case "path":
				c.Path = val
				continue
			}
			c.Unparsed = append(c.Unparsed, parts[i])
		}
		cookies = append(cookies, c)
	}
	return cookies
}

func parseCookieValue(raw string, allowDoubleQuote bool) (string, bool) {
	// Strip the quotes, if present.
	if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	return raw, true
}

func readCookieJson(filepath string) *cookiejar.Jar {
	jar, err := cookiejar.New(nil)

	if err != nil {
		log.Fatal("Error reading cookie file")
	}

	if filepath == "" {

		return jar
	}
	cookieFile, err := os.Open(filepath)
	var cookies CookieInfo

	if err != nil {
		log.Fatal("Error creating cookie jar")
	}

	defer cookieFile.Close()

	bytes, _ := ioutil.ReadAll(cookieFile)

	json.Unmarshal(bytes, &cookies)

	for rawUrl, cookieString := range cookies {
		parsedUrl, err := url.Parse(rawUrl)

		if err != nil {
			continue
		}

		jar.SetCookies(parsedUrl, readCookiesFromString(cookieString))
	}

	return jar
}
