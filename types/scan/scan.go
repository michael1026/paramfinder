package scan

import "sync"

type ReflectedScan struct {
	Stable          bool
	CanaryCount     int
	FoundParameters []string
}

type URLInfo struct {
	Params              []string `json:"params"`
	ReflectedScan       *ReflectedScan
	PotentialParameters map[string]string
	MaxParams           int
}

type ScanResults map[string]*URLInfo

type Scan struct {
	ScanResults      ScanResults
	ScanResultsMutex sync.RWMutex
	WordList         []string
	JsonResults      JsonResults
	JsonResultsMutex sync.RWMutex
}

type JsonResult struct {
	Params []string `json:"params"`
}

type JsonResults map[string]JsonResult

func (s *Scan) FillDefaults() {
	s.JsonResultsMutex = sync.RWMutex{}
	s.ScanResultsMutex = sync.RWMutex{}
	s.ScanResults = make(ScanResults)
	s.JsonResults = make(JsonResults)
}
