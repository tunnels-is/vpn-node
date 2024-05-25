package core

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/tunnels-is/vpn-node/helpers"
	"github.com/tunnels-is/vpn-node/structs"
	"github.com/zveinn/tcpcrypt"
	"golang.org/x/crypto/bcrypt"
)

var (
	TCPControlListener net.Listener
	UDPControlListener net.UDPConn
)

func StartTCPControlListener() {
	var err error
	defer func() {
		helpers.BasicRecover()
		if err != nil {
			LOG_ERROR("Error spawning TCP control listener", err, nil)
		}
		RoutineWatcher <- 3
	}()

	TCPControlListener, err = net.Listen("tcp4", C.InterfaceIP+":"+strconv.Itoa(C.Port))
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		c, err := TCPControlListener.Accept()
		if err != nil {
			continue
		}
		go acceptClientConnection(c)
	}
}

func StartUDPControlListener() {
	// defer func() {
	// 	helpers.BasicRecover()
	// 	if err != nil {
	// 		LOG_ERROR("Error spawning TCP control listener", err, nil)
	// 	}
	// 	RoutineWatcher <- 4
	// }()
	//
	// udpAddr, err := net.ResolveUDPAddr("udp", C.InterfaceIP+":"+strconv.Itoa(C.Port))
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	//
	// UDPControlListener, err := net.ListenUDP("udp", udpAddr)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	//
	// for {
	// 	c, err := UDPControlListener.Accept()
	// 	if err != nil {
	// 		continue
	// 	}
	// 	go acceptClientConnection(c)
	// }
	return
}

func acceptClientConnection(c net.Conn) {
	ES, err := tcpcrypt.NewSocketWrapper(c, tcpcrypt.AES256)
	if err != nil {
		INFO(3, "unable to create encrypted socket, ", err)
		return
	}

	err = ES.ReceiveHandshake()
	if err != nil {
		INFO(3, "unable to receive user handshake, ", err)
		return
	}

	_, data, err := ES.Read()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(data)
	fmt.Println(string(data))
	CCR := new(structs.ClientConnectRequest)
	err = json.Unmarshal(data, &CCR)
	if err != nil {
		fmt.Println("verify login errr:", err)
		return
	}

	// VALIDATE USER
	for u, p := range Auth {
		if u == CCR.Username {
			err = bcrypt.CompareHashAndPassword([]byte(p), []byte(CCR.Password))
			if err != nil {
				c.Close()
				return
			}
		}
	}

	// if CCR.EncType != 3 {
	// 	// IF ENC TYPE == 0 then do nothing ???
	// 	ES, err := tcpcrypt.NewSocketWrapper(c, CCR.EncType)
	// 	if err != nil {
	// 		INFO(3, "unable to create encrypted socket, ", err)
	// 		return
	// 	}
	//
	// 	err = ES.ReceiveHandshake()
	// 	if err != nil {
	// 		INFO(3, "unable to receive user handshake, ", err)
	// 		return
	// 	}
	// }

	AllocR, CPM := CreatePortMapping(CCR)
	if CPM == nil || AllocR == nil {
		c.Close()
		return
	}
	AllocR.Type = CCR.EncType
	CPM.TunnelSocket = c
	CPM.ES = ES

	R := new(structs.FullConnectResponse)
	R.Node = C
	R.Session = AllocR

	respBytes, err := json.Marshal(R)
	if err != nil {
		c.Close()
		return
	}

	_, err = ES.Write(respBytes)
	if err != nil {
		c.Close()
		return
	}

	go ProcessUsersPackets(&SocketProcessorSignal{
		UUID: AllocR.UUID,
	})

	go HandleClientTunnelSocket(&SocketProcessorSignal{
		UUID: AllocR.UUID,
	})

	INFO(3, "++++++++++++++ REPLYING TO PORT ALLOCATION >> ", AllocR.UUID)
}
