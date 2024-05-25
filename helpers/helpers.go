package helpers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/tunnels-is/vpn-node/logging"
	"github.com/tunnels-is/vpn-node/structs"
	"golang.org/x/crypto/bcrypt"
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

func ReadLengthBytesAndDataFromSocket(CONN net.Conn, TunnelBuffer []byte) (DL uint16, err error) {
	var n int
	n, err = io.ReadAtLeast(CONN, TunnelBuffer[0:2], 2)
	if err != nil {
		logging.ERROR(3, "TUNNEL READER ERROR: ", err)
		return
	}

	if n != 2 {
		logging.ERROR(3, "TUNNEL SMALL READ ERROR: ", CONN.RemoteAddr())
		err = errors.New("")
		return
	}

	DL = binary.BigEndian.Uint16(TunnelBuffer[0:2])

	if DL > 0 {
		n, err = io.ReadAtLeast(CONN, TunnelBuffer[2:2+DL], int(DL))
		if err != nil {
			logging.ERROR(3, "TUNNEL DATA READ ERROR: ", err)
			return
		}
	}

	return
}

func ReadAuthConfig(path string) (Auth map[string]string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	Auth = make(map[string]string)
	err = json.Unmarshal(b, &Auth)
	if err != nil {
		panic(err)
	}
	return
}

func ReadNodeConfig(path string) (C *structs.Node) {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	C = new(structs.Node)
	err = json.Unmarshal(b, C)
	if err != nil {
		panic(err)
	}
	return
}

func RemoveUser(user, configPath string) {
	ac := ReadAuthConfig(configPath)
	if ac == nil {
		panic("unable to read config path")
	}
	_, ok := ac[user]
	if !ok {
		return
	}

	delete(ac, user)

	outb, err := json.Marshal(&ac)
	if err != nil {
		panic("unable to marshal config:" + err.Error())
	}

	s, _ := os.Stat(configPath)

	fm := os.FileMode(0o777)
	if s != nil {
		fm = s.Mode()
	}

	err = os.WriteFile(configPath, outb, fm)
	if err != nil {
		panic("unable to save user config:" + err.Error())
	}
}

func CreateNewUserAndPassword(user, pass, configPath string) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 13)
	if err != nil {
		panic("unable to bcrypt password: " + err.Error())
	}

	var ac map[string]string
	s, err := os.Stat(configPath)
	if err != nil || s == nil {

		ac = make(map[string]string)
		ac[user] = string(hash)

	} else {

		ac = ReadAuthConfig(configPath)
		if ac == nil {
			panic("unable to read config path")
		}

		ac[user] = string(hash)
	}

	outb, err := json.Marshal(&ac)
	if err != nil {
		panic("unable to marshal config:" + err.Error())
	}

	fm := os.FileMode(0o777)
	if s != nil {
		fm = s.Mode()
	}

	err = os.WriteFile(configPath, outb, fm)
	if err != nil {
		panic("unable to save user config:" + err.Error())
	}
}
