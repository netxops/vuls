package reporter

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
)

// HTTPRequestWriter writes results to HTTP request
type HTTPRequestWriter struct {
	URL   string
	Token string
}

// Write sends results as HTTP response
func (w HTTPRequestWriter) Write(rs ...models.ScanResult) (err error) {
	//for _, r := range rs {
	//	b := new(bytes.Buffer)
	//	if err := json.NewEncoder(b).Encode(r); err != nil {
	//		return err
	//	}
	//	_, err = http.Post(w.URL, "application/json; charset=utf-8", b)
	//	if err != nil {
	//		return err
	//	}
	//}
	reportMap := make(map[string]models.ScanVulnResult)
	//rcves := []models.VulnInfos{}
	for _, r := range rs {
		//rm = append(rm, r)
		var ScanVulnResult models.ScanVulnResult
		ScanVulnResult.Release = r.Release
		ScanVulnResult.Family = r.Family
		ScanVulnResult.VulnInfos = r.ScannedCves
		reportMap[r.ServerName] = ScanVulnResult
		//rcves = append(rcves, r.ScannedCves)
	}
	//fmt.Println("-----", rcves)
	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(reportMap); err != nil {
		return err
	}

	//_, err = http.Post(w.URL, "application/json; charset=utf-8", b)
	//if err != nil {
	//	return err
	//}
	req, _ := http.NewRequest("POST", w.URL, b)
	req.Header.Add("x-token", w.Token)
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	//body, _ := ioutil.ReadAll(res.Body)

	//fmt.Println("response", res)
	return nil
}

// HTTPResponseWriter writes results to HTTP response
type HTTPResponseWriter struct {
	Writer http.ResponseWriter
}

// Write sends results as HTTP response
func (w HTTPResponseWriter) Write(rs ...models.ScanResult) (err error) {
	res, err := json.Marshal(rs)
	if err != nil {
		return xerrors.Errorf("Failed to marshal scan results: %w", err)
	}
	w.Writer.Header().Set("Content-Type", "application/json")
	_, err = w.Writer.Write(res)

	return err
}
