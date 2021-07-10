package scanhttp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func GetDocFromURL(rawUrl string, client *http.Client) (*goquery.Document, error) {
	req, err := http.NewRequest("GET", rawUrl, nil)

	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return nil, err
	}
	req.Header.Set("Connection", "close")

	// for _, h := range *headers {
	// 	parts := strings.SplitN(h, ":", 2)
	// 	if len(parts) != 2 {
	// 		continue
	// 	}

	// 	req.Header.Set(parts[0], parts[1])
	// }

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

func BuildHttpClient(jar *cookiejar.Jar) (c *http.Client) {
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
