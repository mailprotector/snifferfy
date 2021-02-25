package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
)

var cfg ConfigOptions

type ConfigOptions struct {
	SnfPort    string `env:"SNFPORT" env-default:"9001"`
	HttpPort   string `env:"HTTPPORT" env-default:"8080"`
	WorkingDir string `env:"WORKINGDIR" env-default:"/usr/share/snf-server/storage/"`
	LogLevel   string `env:"LOGLEVEL" env-default:"info"`
}

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
		Log  struct {
			Scan struct {
				TimeStamp   int    `xml:"u,attr"`
				Message     string `xml:"m,attr"`
				Result      int    `xml:"s,attr"`
				RuleId      int    `xml:"r,attr"`
				Performance struct {
					SetupTime  int `xml:"s,attr"`
					ScanTime   int `xml:"t,attr"`
					Bytes      int `xml:"l,attr"`
					Evaluators int `xml:"d,attr"`
				} `xml:"p"`
				Gbudb struct {
					Ordinal     int     `xml:"o,attr"`
					Ip          string  `xml:"i,attr"`
					Flag        string  `xml:"t,attr"`
					Confidence  float32 `xml:"c,attr"`
					Probability float32 `xml:"p,attr"`
					Result      string  `xml:"r,attr"`
				} `xml:"g"`
			} `xml:"s"`
		} `xml:"log"`
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
	log.Debug("raw form data: ", r)
	l := r.FormValue("logEnable")
	x := r.FormValue("xhdrEnable")
	ip := r.FormValue("ip")

	l = setDefault(l, "yes")
	x = setDefault(x, "no")

	if ip == "" {
		log.Error("originating ip address not provided...skipping")
		http.Error(w, "{\"level\":\"error\",\"msg\":\"originating ip address not provided...skipping\"}", http.StatusInternalServerError)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Error(err)
		http.Error(w, fmt.Sprintf("{\"level\":\"error\",\"msg\":\"%v\"}", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	tmpFile, err := ioutil.TempFile(cfg.WorkingDir, "*")
	if err != nil {
		log.Error(err)
		http.Error(w, fmt.Sprintf("{\"level\":\"error\",\"msg\":\"%v\"}", err), http.StatusInternalServerError)
		return
	}
	defer tmpFile.Close()

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Error(err)
	}
	tmpFile.Write(fileBytes)
	log.Debug("saved file %+v as %+v, %+v bytes", handler.Filename, tmpFile.Name(), handler.Size)
	result := snifferScan(tmpFile.Name(), ip, l, x)
	if result != "" {
		io.WriteString(w, result)
	} else {
		http.Error(w, "{\"level\":\"error\",\"msg\":\"received empty response from sniffer\"}", http.StatusInternalServerError)
	}
	defer os.Remove(tmpFile.Name())
}

func httpTestIp(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	ip := r.FormValue("ip")
	result := snifferTestIp(ip)
	if result != "" {
		io.WriteString(w, result)
	} else {
		http.Error(w, "{\"level\":\"error\",\"msg\":\"received empty response from sniffer\"}", http.StatusInternalServerError)
	}
}

func httpStatus(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	interval := r.FormValue("interval")
	result := snifferReport(interval)
	if result != "" {
		io.WriteString(w, result)
	} else {
		http.Error(w, "{\"level\":\"error\",\"msg\":\"received empty response from sniffer\"}", http.StatusInternalServerError)
	}
}

func snifferTestIp(ip string) string {
	xci := fmt.Sprintf("<snf><xci><gbudb><test ip=\"%v\"/></gbudb></xci></snf>", ip)
	log.Debug("sending xci command: ", xci)
	r := sendXci(xci)
	log.Debug("received xci response: ", string(r))
	result := XciToJson(r, "testip")
	return result
}

func snifferScan(file string, ip string, l string, x string) string {
	xci := fmt.Sprintf("<snf><xci><scanner><scan xhdr=\"%v\" log=\"%v\" file=\"%v\" ip=\"%v\"/></scanner></xci></snf>", x, l, file, ip)
	log.Debug("sending xci command: ", xci)
	r := sendXci(xci)
	log.Debug("received xci response: ", string(r))
	result := XciToJson(r, "scan")
	log.Info(result)
	return result
}

func snifferReport(interval string) string {
	xci := fmt.Sprintf("<snf><xci><report><request><status class=\"%v\"/></request></report></xci></snf>", interval)
	log.Debug("sending xci command: ", xci)
	x := sendXci(xci)
	log.Debug("received xci response: ", string(x))
	result := XciToJson(x, "report")
	return result
}

func XciToJson(xci []byte, reqType string) string {
	var data XciResult
	err := xml.Unmarshal(xci, &data)
	if err != nil {
		log.Error("xml conversion failed: ", err)
	}

	log.Debug("unmarshaled xml: ", data)
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
	tcpAddr, err := net.ResolveTCPAddr("tcp", "localhost:"+cfg.SnfPort)
	c, err := net.DialTCP("tcp", nil, tcpAddr)

	if err != nil {
		panic(err.Error())
	}
	return c
}

func connWrite(xci string, c net.Conn) {
	_, err := c.Write([]byte(xci))
	if err != nil {
		log.Error("write to snf-server failed:", err.Error())
	}
}

func connRead(c net.Conn) (int, []byte) {
	buffer := make([]byte, 4096)
	totalBytes := 0

	for {
		n, err := c.Read(buffer)
		totalBytes += n
		log.Debug("connread totalBytes:", totalBytes)
		if err != nil {
			if err != io.EOF {
				log.Error("read from snf-server failed: ", err.Error())
			}
			break
		}
	}
	return totalBytes, buffer
}

func setDefault(v string, d string) string {
	if v == "" {
		return d
	} else {
		return v
	}
}

func setupLogging(logLevel string) {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	if logLevel == "info" {
		log.SetLevel(log.InfoLevel)
	} else if logLevel == "debug" {
		log.SetLevel(log.DebugLevel)
	}
}

func setupRoutes() {
	http.HandleFunc("/ping", httpPing)
	http.HandleFunc("/scan", httpScan)
	http.HandleFunc("/testip", httpTestIp)
	http.HandleFunc("/status", httpStatus)

	log.Info("initialized snifferfy on port ", cfg.HttpPort)
	err := http.ListenAndServe(":"+cfg.HttpPort, nil)
	if err != nil {
		log.Panic(err)
	}
}

func init() {
	// config
	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		panic(err)
	}

	// logging
	setupLogging(cfg.LogLevel)
}

func main() {
	setupRoutes()
}
