package scan

type ReflectedScan struct {
	Stable          bool
	CanaryCount     int
	FoundParameters []string
}

type URLInfo struct {
	Params              []string `json:"params"`
	ReflectedScan       *ReflectedScan
	PotentialParameters map[string]string
}

type ScanResults map[string]*URLInfo

type Scan struct {
	ScanResults ScanResults
	WordList    []string
	JsonResults JsonResults
}

type JsonResult struct {
	Params []string `json:"params"`
}

type JsonResults map[string]JsonResult
