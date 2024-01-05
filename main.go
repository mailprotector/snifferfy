package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
)

var cfg ConfigOptions

type ConfigOptions struct {
	SnfPort    string  `env:"SNFPORT" env-default:"9001"`
	SnfHost    string  `env:"SNFHOST" env-default:"127.0.0.1"`
	SnfTimeout float32 `env:"SNFTIMEOUT" env-default:"5"`
	HttpPort   string  `env:"HTTPPORT" env-default:"8080"`
	WorkingDir string  `env:"WORKINGDIR" env-default:"/usr/share/snf-server/storage/"`
	LogLevel   string  `env:"LOGLEVEL" env-default:"info"`
}

type XciResult struct {
	IpResult struct {
		Ip          string  `xml:"ip,attr"`
		Type        string  `xml:"type,attr"`
		Range       string  `xml:"range,attr"`
		Code        int     `xml:"code,attr"`
		Probability float32 `xml:"p,attr"`
		Confidence  float32 `xml:"c,attr"`
		Bad         int     `xml:"b,attr"`
		Good        int     `xml:"g,attr"`
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

func httpHealth(w http.ResponseWriter, r *http.Request) {
	uuid := uuid.New()
	reqId := uuid.String()
	_, err := snifferReport(reqId, "5")

	if err != nil {
		writeLogLine("error", "httpHealth", reqId, err.Error())
		writeHttpError(reqId, w, fmt.Sprintf("%v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	result := "{\"result\": alive}"

	writeLogLine("debug", "httpHealth", reqId, result)
	io.WriteString(w, result)
}

func httpScan(w http.ResponseWriter, r *http.Request) {
	uuid := uuid.New()
	reqId := uuid.String()
	l := r.Header.Get("logEnable")
	x := r.Header.Get("xhdrEnable")
	ip := r.Header.Get("ip")
	id := r.Header.Get("requestId")

	l = setDefault(l, "yes")
	x = setDefault(x, "no")

	if id != "" {
		reqId = id
	}

	reqBody, err := io.ReadAll(r.Body)

	if err != nil {
		writeLogLine("error", "httpScan", reqId, err.Error())
		writeHttpError(reqId, w, fmt.Sprintf("%v", err.Error()))
		return
	}

	tmpFile, err := os.CreateTemp(cfg.WorkingDir, "*")

	if err != nil {
		writeLogLine("error", "httpScan", reqId, err.Error())
		writeHttpError(reqId, w, fmt.Sprintf("%v", err.Error()))
		return
	}

	tmpFile.Write(reqBody)
	tmpFile.Close()
	writeLogLine("debug", "httpScan", reqId, fmt.Sprintf("{\"file_write\":\"%v\"}", tmpFile.Name()))
	writeLogLine("debug", "httpScan", reqId, fmt.Sprintf("{\"ip\":\"%v\"}", ip))

	result, err := snifferScan(reqId, tmpFile.Name(), ip, l, x)

	writeLogLine("debug", "httpScan", reqId, fmt.Sprintf("{\"file_delete\":\"%v\"}", tmpFile.Name()))
	os.Remove(tmpFile.Name())

	if result != "" {
		writeLogLine("info", "httpScan", reqId, result)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, result)
		return
	} else {
		writeLogLine("error", "httpScan", reqId, err.Error())
		writeHttpError(reqId, w, fmt.Sprintf("%v", err.Error()))
	}
}

func httpTestIp(w http.ResponseWriter, r *http.Request) {
	uuid := uuid.New()
	reqId := uuid.String()
	ip := r.Header.Get("ip")
	id := r.Header.Get("requestId")

	if id != "" {
		reqId = id
	}

	if ip == "" {
		writeLogLine("error", "httpTestIp", reqId, "must include ip to search")
		writeHttpError(reqId, w, fmt.Sprintf("must include ip to search"))
		return
	} else {
		writeLogLine("debug", "httpTestIp", reqId, fmt.Sprintf("{\"ip\":\"%v\"}", ip))
	}

	result, err := snifferTestIp(reqId, ip)

	if err != nil {
		writeLogLine("error", "httpTestIp", reqId, err.Error())
		writeHttpError(reqId, w, fmt.Sprintf("%v", err.Error()))
		return
	}

	writeLogLine("info", "httpTestIp", reqId, result)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, result)
}

func httpStatus(w http.ResponseWriter, r *http.Request) {
	uuid := uuid.New()
	reqId := uuid.String()
	interval := r.Header.Get("interval")

	if (interval != "second") && (interval != "minute") && (interval != "hour") {
		writeHttpError(reqId, w, fmt.Sprintf("must include interval"))
		writeLogLine("error", "httpStatus", reqId, "must include interval")
		return
	}

	result, err := snifferReport(reqId, interval)

	if err != nil {
		writeLogLine("error", "httpStatus", reqId, err.Error())
		writeHttpError(reqId, w, fmt.Sprintf("%v", err))
		return
	}

	writeLogLine("info", "httpStatus", reqId, result)
	io.WriteString(w, result)
}

func snifferTestIp(reqId string, ip string) (string, error) {
	xci := fmt.Sprintf("<snf><xci><gbudb><test ip=\"%v\"/></gbudb></xci></snf>", ip)

	writeLogLine("debug", "snifferTestIp", reqId, fmt.Sprintf("{\"command\":\"%v\"}", xci))
	r, err := sendXci(reqId, xci)

	if err != nil {
		writeLogLine("error", "snifferTestIp", reqId, err.Error())
		return "", err
	}

	writeLogLine("debug", "snifferTestIp", reqId, fmt.Sprintf("{\"response\":\"%v\"}", string(r)))
	result := XciToJson(reqId, r, "testip")

	return result, nil
}

func snifferScan(reqId string, file string, ip string, l string, x string) (string, error) {
	var xci string

	if ip == "" {
		xci = fmt.Sprintf("<snf><xci><scanner><scan xhdr=\"%v\" log=\"%v\" file=\"%v\"/></scanner></xci></snf>", x, l, file)
	} else {
		xci = fmt.Sprintf("<snf><xci><scanner><scan xhdr=\"%v\" log=\"%v\" file=\"%v\" ip=\"%v\"/></scanner></xci></snf>", x, l, file, ip)
	}

	writeLogLine("debug", "snifferScan", reqId, fmt.Sprintf("{\"command\":\"%v\"}", xci))
	r, err := sendXci(reqId, xci)

	if err != nil {
		writeLogLine("error", "snifferScan", reqId, err.Error())
		return "", err
	}
	writeLogLine("debug", "snifferScan", reqId, fmt.Sprintf("{\"response\":\"%v\"}", string(r)))
	result := XciToJson(reqId, r, "scan")

	return result, nil
}

func snifferReport(reqId string, interval string) (string, error) {
	xci := fmt.Sprintf("<snf><xci><report><request><status class=\"%v\"/></request></report></xci></snf>", interval)
	writeLogLine("debug", "snifferReport", reqId, fmt.Sprintf("{\"command\":\"%v\"}", xci))
	r, err := sendXci(reqId, xci)

	if err != nil {
		writeLogLine("error", "snifferReport", reqId, err.Error())
		return "", err
	}

	writeLogLine("debug", "snifferReport", reqId, fmt.Sprintf("{\"response\":\"%v\"}", string(r)))
	result := XciToJson(reqId, r, "report")

	return result, nil
}

func XciToJson(reqId string, xci []byte, reqType string) string {
	var data XciResult
	err := xml.Unmarshal(xci, &data)
	if err != nil {
		writeLogLine("error", "XciToJson", reqId, err.Error())
	}

	writeLogLine("debug", "XciToJson", reqId, fmt.Sprintf("{\"unmarshaled_xml\":\"%v\"}", data))
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

func sendXci(reqId string, cmd string) ([]byte, error) {
	conn, err := connInit(reqId)

	if err != nil {
		writeLogLine("error", "sendXci", reqId, err.Error())
		return nil, err
	}

	writeLogLine("debug", "sendXci", reqId, fmt.Sprintf("{\"command\":\"%v\"}", cmd))
	connWrite(reqId, cmd, conn)
	resp := connRead(reqId, conn)
	defer conn.Close()
	return resp, nil
}

func connInit(reqId string) (net.Conn, error) {
	writeLogLine("debug", "connInit", reqId, cfg.SnfHost+":"+cfg.SnfPort)

	d := net.Dialer{Timeout: time.Second * 5}
	c, err := d.Dial("tcp", cfg.SnfHost+":"+cfg.SnfPort)

	if err != nil {
		return nil, err
	}

	return c, nil
}

func connWrite(reqId string, xci string, c net.Conn) {
	_, err := c.Write([]byte(xci))
	if err != nil {
		writeLogLine("error", "connWrite", reqId, err.Error())
	}
}

func connRead(reqId string, c net.Conn) []byte {

	resp, err := io.ReadAll(c)
	if err != nil {
		writeLogLine("error", "connRead", reqId, err.Error())
	}

	writeLogLine("debug", "connRead", reqId, fmt.Sprintf("{\"response\":\"%v\"}", resp))
	return resp
}

func writeHttpError(reqId string, w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	io.WriteString(w, fmt.Sprintf("{\"level\":\"error\",\"msg\":\"%v\"}", msg))
	writeLogLine("error", "writeHttpError", reqId, msg)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	uuid := uuid.New()
	reqId := uuid.String()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "{\"level\":\"error\",\"msg\":\"endpoint not found\"}")
	writeLogLine("info", "notFound", reqId, "endpoint not found")
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

func writeLogLine(level string, function string, reqId string, msg string) {
	if level == "info" {
		log.WithFields(log.Fields{
			"function":   function,
			"request_id": reqId,
		}).Info(msg)
	} else if level == "error" {
		log.WithFields(log.Fields{
			"function":   function,
			"request_id": reqId,
		}).Error(msg)
	} else if level == "debug" {
		log.WithFields(log.Fields{
			"function":   function,
			"request_id": reqId,
		}).Debug(msg)
	}
}

func setupRoutes() {
	r := mux.NewRouter()
	r.NotFoundHandler = http.HandlerFunc(notFound)

	r.HandleFunc("/health", httpHealth)
	r.HandleFunc("/scan", httpScan)
	r.HandleFunc("/testip", httpTestIp)
	r.HandleFunc("/status", httpStatus)

	writeLogLine("info", "setupRoutes", "0", fmt.Sprintf("initialized snifferfy on port %v", cfg.HttpPort))
	srv := &http.Server{
		Addr:         "0.0.0.0:" + cfg.HttpPort,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	// config
	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Panic(err)
	}

	// logging
	setupLogging(cfg.LogLevel)
}

func main() {
	setupRoutes()
}
