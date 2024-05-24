package helpers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/tunnels-is/vpn-node/logging"
)

const (
	ERROR_InvalidInput = ""
)

var (
	LOG_DEBUG = logging.Debug
	LOG_INFO  = logging.Info
	LOG_ERROR = logging.Error
)

func RecoverWithDebugLog(msg string, printExit bool, err error, data map[string]interface{}) {
	r := recover()
	if r != nil {
		LOG_DEBUG(msg, r, true, data)
	} else if err != nil {
		LOG_ERROR(msg, err, data)
	} else if printExit {
		LOG_INFO(msg, data)
	}
}

func BasicRecover() {
	if r := recover(); r != nil {
		LOG_DEBUG("PANIC", r, true, nil)
	}
}

func CopySlice(in []byte) (out []byte) {
	out = make([]byte, len(in))

	return
}

func SendRequestToController(
	IP, Port string,
	method string,
	route string,
	data interface{},
	timeoutMS int,
	sendPrefix bool,
) (error, []byte, int) {
	var err error
	start := time.Now()
	defer func() {
		duration := time.Since(start).Milliseconds()
		if duration > 3000 || err != nil {
			LOG_ERROR("forward to controller is slow", err, map[string]interface{}{
				"ip":         IP,
				"port":       Port,
				"method":     method,
				"route":      route,
				"durationMS": fmt.Sprintf("%d", duration),
			})
		}
	}()
	defer RecoverWithDebugLog("SEND REQUEST TO CONTROLLER", false, err, map[string]interface{}{
		"err":    err,
		"ip":     IP,
		"port":   Port,
		"method": method,
		"route":  route,
	})

	var body []byte
	if data != nil {
		body, err = json.Marshal(data)
		if err != nil {
			return err, nil, 0
		}
	}

	var req *http.Request

	if method == "POST" {
		req, err = http.NewRequest(method, "https://"+IP+":"+Port+"/"+route, bytes.NewBuffer(body))
	} else if method == "GET" {
		req, err = http.NewRequest(method, "https://"+IP+":"+Port+"/"+route, nil)
	} else {
		return errors.New("HTTP METHOD NOT SUPPORTED:" + method), nil, 0
	}

	if err != nil {
		return err, nil, 0
	}

	req.Header.Add("Content-Type", "application/json")

	client := new(http.Client)
	client.Timeout = time.Duration(timeoutMS) * time.Millisecond
	client.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (conn net.Conn, err error) {
			conn, err = net.Dial("tcp", IP+":"+Port)
			if err != nil {
				return
			}
			if sendPrefix {
				_, err = conn.Write([]byte{255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
				if err != nil {
					return
				}
			}
			return
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		if resp != nil {
			return err, nil, resp.StatusCode
		} else {
			return err, nil, 0
		}
	}

	defer func() {
		if client != nil {
			client.CloseIdleConnections()
		}
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	var x []byte
	x, err = io.ReadAll(resp.Body)
	if err != nil {
		return err, nil, resp.StatusCode
	}

	return nil, x, resp.StatusCode
}
