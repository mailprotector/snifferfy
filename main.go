package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

var debug bool = false
var workingDir = "/usr/share/snf-server/storage/"
var snifferHost = "localhost:9001"

type XciResult struct {
	IpResult struct {
		Ip          string `xml:"ip,attr"`
		Type        string `xml:"type,attr"`
		Range       string `xml:"range,attr"`
		Code        int    `xml:"code,attr"`
		Probability int    `xml:"p,attr"`
		Confidence  int    `xml:"c,attr"`
		Bad         int    `xml:"b,attr"`
		Good        int    `xml:"g,attr"`
	} `xml:"xci>gbudb>result"`
	ScanResult struct {
		Code int    `xml:"code,attr"`
		Xhdr string `xml:"xhdr"`
	} `xml:"xci>scanner>result"`
	ReportResult struct {
		Stats struct {
			NodeId   string `xml:"nodeid,attr"`
			Basetime int    `xml:"basetime,attr"`
			Elapsed  int    `xml:"elapsed,attr"`
			Class    string `xml:"class,attr"`
			Version  struct {
				Engine   string `xml:"engine"`
				Platform string `xml:"platform"`
			} `xml:"version"`
			Timers struct {
				Run struct {
					Started int `xml:"started,attr"`
					Elapsed int `xml:"elapsed,attr"`
				} `xml:"run"`
				Sync struct {
					Latest  int `xml:"latest,attr"`
					Elapsed int `xml:"elapsed,attr"`
				} `xml:"sync"`
				Save struct {
					Latest  int `xml:"latest,attr"`
					Elapsed int `xml:"elapsed,attr"`
				} `xml:"save"`
				Condense struct {
					Latest  int `xml:"latest,attr"`
					Elapsed int `xml:"elapsed,attr"`
				} `xml:"condense"`
			} `xml:"timers"`
			Gbudb struct {
				Size struct {
					Bytes int `xml:"bytes,attr"`
				} `xml:"size"`
				Records struct {
					Count int `xml:"count,attr"`
				} `xml:"records"`
				Utilization struct {
					Percent float32 `xml:"percent,attr"`
				} `xml:"utilization"`
			} `xml:"gbudb"`
			Rules struct {
				Rulesbase struct {
					Utc int `xml:"utc,attr"`
				} `xml:"rulesbase"`
				Active struct {
					Utc int `xml:"utc,attr"`
				} `xml:"active"`
				Update struct {
					Ready string `xml:"ready,attr"`
					Utc   int    `xml:"utc,attr"`
				} `xml:"update"`
				Latest struct {
					Rule string `xml:"rule,attr"`
				} `xml:"latest"`
			} `xml:"rules"`
		} `xml:"stats"`
	} `xml:"xci>report>response"`
}

func httpPing(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "pong\n")
}

func httpScan(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	ip := r.FormValue("ip")
	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	tmpFile, err := ioutil.TempFile(workingDir, "*")
	if err != nil {
		log.Println(err)
	}
	defer tmpFile.Close()

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println(err)
	}
	tmpFile.Write(fileBytes)
	log.Printf("saved file %+v as %+v, %+v bytes", handler.Filename, tmpFile.Name(), handler.Size)

	// send XCI command to sniffer and get json-encoded result
	result := snifferScan(tmpFile.Name(), ip)
	io.WriteString(w, result)

	// remove temp file
	defer os.Remove(tmpFile.Name())
}

func httpTestIp(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	ip := r.FormValue("ip")

	// send XCI command to sniffer and get json-encoded result
	result := snifferTestIp(ip)
	io.WriteString(w, result)
}

func httpStatus(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	interval := r.FormValue("interval")

	result := snifferReport(interval)
	io.WriteString(w, result)
}

func snifferTestIp(ip string) string {
	xci := fmt.Sprintf("<snf><xci><gbudb><test ip=\"%v\"/></gbudb></xci></snf>", ip)
	log.Println("sending xci command: ", xci)
	x := sendXci(xci)
	log.Println("received xci response: ", string(x))
	result := XciToJson(x, "testip")
	return result
}

func snifferScan(file string, ip string) string {
	xci := fmt.Sprintf("<snf><xci><scanner><scan xhdr=\"yes\" log=\"yes\" file=\"%v\" ip=\"%v\"/></scanner></xci></snf>", file, ip)
	log.Println("sending xci command: ", xci)
	x := sendXci(xci)
	log.Println("received xci response: ", string(x))
	result := XciToJson(x, "scan")
	return result
}

func snifferReport(interval string) string {
	xci := fmt.Sprintf("<snf><xci><report><request><status class=\"%v\"/></request></report></xci></snf>", interval)
	log.Println("sending xci command: ", xci)
	x := sendXci(xci)
	log.Println("received xci response: ", string(x))
	result := XciToJson(x, "report")
	return result
}

func XciToJson(xci []byte, reqType string) string {
	var data XciResult
	err := xml.Unmarshal(xci, &data)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("unmarshaled xml: ", data)
	switch reqType {
	case "scan":
		json, _ := json.Marshal(data.ScanResult)
		return fmt.Sprintf("%s", string(json))
	case "testip":
		json, _ := json.Marshal(data.IpResult)
		return fmt.Sprintf("%s", string(json))
	case "report":
		json, _ := json.Marshal(data.ReportResult)
		return fmt.Sprintf("%s", string(json))
	default:
		return "no response"
	}

}

func sendXci(cmd string) []byte {
	conn := connInit()
	connWrite(cmd, conn)
	tBytes, resp := connRead(conn)
	return resp[:tBytes]
}

func connInit() net.Conn {
	tcpAddr, err := net.ResolveTCPAddr("tcp", snifferHost)
	c, err := net.DialTCP("tcp", nil, tcpAddr)

	if err != nil {
		log.Println("connection to snf-server failed:", err.Error())
	}
	return c
}

func connWrite(xci string, c net.Conn) {
	_, err := c.Write([]byte(xci))
	if err != nil {
		log.Println("write to snf-server failed:", err.Error())
	}
}

func connRead(c net.Conn) (int, []byte) {
	buffer := make([]byte, 4096)
	totalBytes := 0

	for {
		n, err := c.Read(buffer)
		totalBytes += n
		//log.Println("connread totalBytes:", totalBytes)
		if err != nil {
			if err != io.EOF {
				log.Println("read from snf-server failed: ", err.Error())
			}
			break
		}
	}
	return totalBytes, buffer
}

func setupRoutes() {
	http.HandleFunc("/ping", httpPing)
	http.HandleFunc("/scan", httpScan)
	http.HandleFunc("/testip", httpTestIp)
	http.HandleFunc("/status", httpStatus)
	log.Println("listening on port 8080")
	log.Println("initialized snifferfy")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	setupRoutes()
}
