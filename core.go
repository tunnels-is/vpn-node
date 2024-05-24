package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/tunnels-is/vpn-node/helpers"
	"github.com/tunnels-is/vpn-node/router"
	"github.com/tunnels-is/vpn-node/structs"
	"github.com/tunnels-is/vpn-node/transportfilter"
	"github.com/zveinn/tcpcrypt"
	"github.com/zveinn/tunnels"
)

func findInterfaceName() (name string) {
	ifs, _ := net.Interfaces()
	for _, v := range ifs {
		addrs, _ := v.Addrs()
		for _, vv := range addrs {
			_, ipnetA, _ := net.ParseCIDR(vv.String())
			if ipnetA.Contains(INTERFACE_IP) {
				name = v.Name
			}
		}
	}
	return
}

func createRawUDPSocket() (
	buffer []byte,
	socket *tunnels.RawSocket,
	err error,
) {
	interfaceString := ""
	defer func() {
		helpers.BasicRecover()
		if err != nil {
			LOG_ERROR(
				"error creating raw UDP socket",
				err,
				map[string]interface{}{
					"interfaceName":   InterfaceName,
					"interfaceIP":     C.InterfaceIP,
					"interfaceString": interfaceString,
				},
			)
		}
	}()

	interfaceString = findInterfaceName()
	if interfaceString == "" {
		err = errors.New("no interface found")
		return
	}

	LOG_INFO("initializing raw UDP socket",
		map[string]interface{}{
			"interfaceName": InterfaceName,
			"interfaceIP":   C.InterfaceIP,
			"interface":     interfaceString,
		},
	)

	buffer = make([]byte, math.MaxUint16)
	socket = &tunnels.RawSocket{
		InterfaceName: interfaceString,
		SocketBuffer:  buffer,
		Domain:        syscall.AF_INET,
		Type:          syscall.SOCK_RAW,
		Proto:         syscall.IPPROTO_UDP,
	}

	err = socket.Create()
	if err != nil {
		return
	}

	UDPRWC = socket.RWC

	return
}

func ReadFromRawUDPSocket() {
	var err error
	defer func() {
		helpers.BasicRecover()
		if err != nil {
			LOG_ERROR("error when reading from raw UDP socket", err, nil)
		}
		RoutineWatcher <- 17
	}()

	var buffer []byte
	var socket *tunnels.RawSocket
	buffer, socket, err = createRawUDPSocket()
	if err != nil {
		time.Sleep(1 * time.Second)
		return
	}

	var n int
	var DSTP uint16
	var IHL byte
	var PM *PORT_RANGE

	for {
		n, err = socket.RWC.Read(buffer)
		if err != nil {
			return
		}

		if n <= 0 {
			time.Sleep(10 * time.Microsecond)
			continue
		}

		// if buffer[9] != 17 && buffer[9] != 6 {
		// 	continue
		// }

		// TODO -- simplify (probably use a mask)
		IHL = ((buffer[0] << 4) >> 4) * 4
		DSTP = binary.BigEndian.Uint16(buffer[IHL+2 : IHL+4])
		PM = PORT_TO_CLIENT_MAPPING[DSTP]
		if PM == nil || PM.Client == nil {
			continue
		}

		if PM.Client.Packets == nil {
			LOG_ADMIN("client queue is nil", map[string]interface{}{
				"StartPort":  PM.StartPort,
				"EndPort":    PM.EndPort,
				"readertype": "UDP",
			})
			continue
		}

		select {
		case PM.Client.Packets <- helpers.CopySlice(buffer[:n]):
			// fmt.Println("UDPIN:", len(buffer[:n]))
		default:
			LOG_INFO("client queue is full", map[string]interface{}{
				"StartPort":  PM.StartPort,
				"EndPort":    PM.EndPort,
				"readertype": "UDP",
			})
		}

	}
}

func createRawTCPSocket() (
	buffer []byte,
	socket *tunnels.RawSocket,
	err error,
) {
	interfaceString := ""
	defer func() {
		helpers.BasicRecover()
		if err != nil {
			LOG_ERROR(
				"error creating raw TCP socket",
				err,
				map[string]interface{}{
					"interfaceName":   InterfaceName,
					"interfaceIP":     C.InterfaceIP,
					"interfaceString": interfaceString,
				},
			)
		}
	}()

	interfaceString = findInterfaceName()
	if interfaceString == "" {
		err = errors.New("no interface found")
		return
	}

	LOG_INFO("initializing raw TCP socket",
		map[string]interface{}{
			"interfaceName":   InterfaceName,
			"interfaceIP":     C.InterfaceIP,
			"interfaceString": interfaceString,
		},
	)

	buffer = make([]byte, math.MaxUint16)
	socket = &tunnels.RawSocket{
		InterfaceName: interfaceString,
		SocketBuffer:  buffer,
		Domain:        syscall.AF_INET,
		Type:          syscall.SOCK_RAW,
		Proto:         syscall.IPPROTO_TCP,
	}

	err = socket.Create()
	if err != nil {
		return
	}

	TCPRWC = socket.RWC

	return
}

func ReadFromRawTCPSocket() {
	var err error
	defer func() {
		helpers.BasicRecover()
		if err != nil {
			LOG_ERROR("error when reading from raw TCP socket", err, nil)
		}
		RoutineWatcher <- 6
	}()

	var buffer []byte
	var socket *tunnels.RawSocket
	buffer, socket, err = createRawTCPSocket()
	if err != nil {
		time.Sleep(1 * time.Second)
		return
	}

	var n int
	var DSTP uint16
	var IHL byte
	var PM *PORT_RANGE

	for {
		n, err = socket.RWC.Read(buffer)
		if err != nil {
			fmt.Println("ERR READ", err)
			return
		}

		if n <= 0 {
			time.Sleep(10 * time.Microsecond)
			continue
		}

		// TODO -- simplify (probably use a mask)
		IHL = ((buffer[0] << 4) >> 4) * 4
		DSTP = binary.BigEndian.Uint16(buffer[IHL+2 : IHL+4])
		PM = PORT_TO_CLIENT_MAPPING[DSTP]
		if PM == nil || PM.Client == nil {
			continue
		}

		if PM.Client.Packets == nil {
			LOG_ADMIN("client queue is nil", map[string]interface{}{
				"StartPort":  PM.StartPort,
				"EndPort":    PM.EndPort,
				"readertype": "TCP",
			})
			continue
		}

		select {
		case PM.Client.Packets <- helpers.CopySlice(buffer[:n]):
		// fmt.Println("TCPIN:", len(buffer[:n]))
		default:
			LOG_INFO("client queue is full", map[string]interface{}{
				"StartPort":  PM.StartPort,
				"EndPort":    PM.EndPort,
				"readertype": "TCP",
			})
		}

	}
}

func InitializeRouterControlSocket() {
	var err error
	defer func() {
		helpers.BasicRecover()
		time.Sleep(500 * time.Millisecond)
		if AR.TCPControllerConnection != nil {
			AR.TCPControllerConnection.Close()
			AR.TCPControllerConnection = nil
		}

		if err != nil {
			LOG_ERROR(
				"unable to connect to active router",
				err,
				map[string]interface{}{
					"publicIP":   AR.PublicIP,
					"routerPort": C.RouterPort,
				},
			)
		}

		RoutineWatcher <- 4
	}()

	if AR == nil {
		return
	}

	AR.ConnectionAttempts++

	AR.TCPControllerConnection, err = net.Dial("tcp", AR.PublicIP+":"+strconv.Itoa(C.RouterPort))
	if err != nil {
		return
	}

	_ = AR.TCPControllerConnection.SetWriteDeadline(time.Now().Add(20 * time.Second))

	_, err = AR.TCPControllerConnection.Write(
		[]byte{router.CODE_ConnectingToControlSocket, 0, 0},
	)
	if err != nil {
		return
	}

	AR.ERS, err = tcpcrypt.NewSocketWrapper(AR.TCPControllerConnection, tcpcrypt.AES256)
	if err != nil {
		return
	}

	err = AR.ERS.InitHandshake()
	if err != nil {
		return
	}

	ConnectRequest := new(structs.NodeConnectRequest)
	ConnectRequest.APIKey = C.APIKey

	var CRBytes []byte
	CRBytes, err = json.Marshal(ConnectRequest)
	if err != nil {
		return
	}

	_ = AR.TCPControllerConnection.SetWriteDeadline(time.Now().Add(20 * time.Second))

	_, err = AR.ERS.Write(CRBytes)
	if err != nil {
		return
	}

	LOG_INFO(
		"controller connected",
		map[string]interface{}{
			"publicIP":   AR.PublicIP,
			"routerPort": AR.Port,
		},
	)

	_ = AR.TCPControllerConnection.SetWriteDeadline(time.Time{})

	var data []byte
	for {
		_ = AR.TCPControllerConnection.SetReadDeadline(
			time.Now().Add(30 * time.Second),
		)

		_, data, err = AR.ERS.Read()
		if err != nil {
			// if errors.Is(err, os.ErrDeadlineExceeded) {
			// }
			return
		}

		LOG_INFO("read from router", map[string]interface{}{
			"data": data,
		})

		if data[0] == router.CODE_InitializingPortAllocation {
			CREATE_CLIENT_PORT_MAPPING(helpers.CopySlice(data[1:]))
		} else if data[0] == router.CODE_pingPong {
			AR.LastPing = time.Now()
		}
	}
}

func GetClientPortMapping(uuid string) *CLIENT_PORT_MAPPING {
	for i := range CLIENT_PORT_MAPPINGS {
		if CLIENT_PORT_MAPPINGS[i] == nil {
			continue
		}
		if CLIENT_PORT_MAPPINGS[i].UUID == uuid {
			return CLIENT_PORT_MAPPINGS[i]
		}

	}
	return nil
}

func RemoveClientPortMapping(uuid string) {
	for i := range CLIENT_PORT_MAPPINGS {
		if CLIENT_PORT_MAPPINGS[i] == nil {
			continue
		}
		if CLIENT_PORT_MAPPINGS[i].UUID == uuid {
			CLIENT_PORT_MAPPINGS[i] = nil
		}

	}
	return
}

func CreateAndAssignClientPortMapping() (index int) {
	CLIENT_LOCK.Lock()
	defer CLIENT_LOCK.Unlock()
	defer helpers.RecoverWithDebugLog(
		"error when creating port mapping",
		false,
		nil,
		map[string]interface{}{
			"publicIP":   AR.PublicIP,
			"routerPort": C.RouterPort,
		},
	)

	for i := range CLIENT_PORT_MAPPINGS {
		if CLIENT_PORT_MAPPINGS[i] == nil {
			index = i
			CLIENT_PORT_MAPPINGS[i] = new(CLIENT_PORT_MAPPING)
			CLIENT_PORT_MAPPINGS[i].Packets = make(chan []byte, 100000)
			CLIENT_PORT_MAPPINGS[i].LastPingFromClient = time.Now()
			break
		}
	}
	return
}

func NukeClient(CM *CLIENT_PORT_MAPPING) {
	if CM == nil {
		return
	}

	INFO(3, "CLOSING CLIENT", CM.UUID)
	if CM.TunnelSocket != nil {
		CM.TunnelSocket.Close()
	}

	close(CM.Packets)

	for i := range PORT_TO_CLIENT_MAPPING {
		if PORT_TO_CLIENT_MAPPING[i] == nil {
			continue
		}

		if PORT_TO_CLIENT_MAPPING[i].StartPort == CM.PORT_RANGE.StartPort {
			PORT_TO_CLIENT_MAPPING[i].Client = nil
		}
	}

	RemoveClientPortMapping(CM.UUID)
}

func HandleClientTunnelSocket(P *SocketProcessorSignal) {
	shouldRestart := true
	defer func() {
		if r := recover(); r != nil {
			INFO(3, r, string(debug.Stack()))
		}

		if shouldRestart {
			TUNNEL_PROCESSOR_MONITOR <- P
		}
	}()

	CM := GetClientPortMapping(P.UUID)
	if CM == nil {
		shouldRestart = false
		return
	}
	if CM.TunnelSocket == nil {
		shouldRestart = false
		return
	}

	defer func() {
		if shouldRestart {
			return
		}
		NukeClient(CM)
	}()

	var err error
	var data []byte
	var NETIP net.IP

	for {
		_, data, err = CM.ES.Read()
		if err != nil {
			shouldRestart = false
			ERR(3, "DATA LENGTH READ ERROR", err)
			return
		}
		if data[0] == 255 {
			CM.LastPingFromClient = time.Now()
			continue
		}

		NETIP = data[16:20]
		if !C.LocalNetworkAccess {
			if transportfilter.IS_LOCAL(NETIP) {
				continue
			}
		}
		if !C.InternetAccess {
			if !transportfilter.IS_LOCAL(NETIP) {
				continue
			}
		}

		if data[9] == 17 {
			_, err = UDPRWC.Write(data)
		} else {
			_, err = TCPRWC.Write(data)
		}

		if err != nil {
			INFO(3, "Could not write on tunnel:", err)
			// egressPacket := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
			// fmt.Println(egressPacket)
			continue
		}

	}
}

func ProcessUsersPackets(P *SocketProcessorSignal) {
	shouldRestart := true
	defer func() {
		if r := recover(); r != nil {
			INFO(3, r, string(debug.Stack()))
		}

		if shouldRestart {
			PACKET_PROCESSOR_MONITOR <- P
		}
		INFO(3, "CLIENT QUEUE returning")
	}()

	CM := GetClientPortMapping(P.UUID)
	if CM == nil {
		shouldRestart = false
		return
	}

	var PACKET []byte
	var NETIP net.IP
	var err error
	IFipTo4 := INTERFACE_IP.To4()
	var ok bool

	for {
		PACKET, ok = <-CM.Packets
		if !ok {
			return
		}
		if PACKET[0] == router.CODE_pingPong {
			// fmt.Println("SENDING PING:", PACKET)
			_, err = CM.ES.Write(PACKET)
			if err != nil {
				fmt.Println("CLIENT WRITE ERROR:", err)
				return
			}
			continue
		}

		if len(PACKET) < 20 {
			continue
		}

		if PACKET[9] != 6 && PACKET[9] != 17 {
			continue
		}

		NETIP = PACKET[16:20]
		if !bytes.Equal(NETIP, IFipTo4) {
			continue
		}

		_, err = CM.ES.Write(PACKET)
		if err != nil {
			fmt.Println("CLIENT WRITE ERROR:", err)
			return
		}
	}
}

func CREATE_CLIENT_PORT_MAPPING(data []byte) {
	defer func() {
		if r := recover(); r != nil {
			INFO(3, r, string(debug.Stack()))
		}
	}()

	NSRequest := new(structs.NewNodeSocketAllocationRequest)
	err := json.Unmarshal(data, NSRequest)
	if err != nil {
		INFO(3, "Broken diffie helman from client >> ", err)
		return
	}

	index := CreateAndAssignClientPortMapping()
	CLIENT_PORT_MAPPINGS[index].UUID = NSRequest.UUID
	fmt.Println("VERSION FROM CLIENT: ", NSRequest.Version)
	CLIENT_PORT_MAPPINGS[index].Version = NSRequest.Version

	var PR *PORT_RANGE

	for i := range PORT_TO_CLIENT_MAPPING {
		if i < int(C.StartPort) {
			continue
		}

		if PORT_TO_CLIENT_MAPPING[i] == nil {
			INFO(3, "PORT TO CLIENT MAPPING IS NIL: ", i)
			continue
		}
		if PORT_TO_CLIENT_MAPPING[i].Client == nil {
			PORT_TO_CLIENT_MAPPING[i].Client = CLIENT_PORT_MAPPINGS[index]
			PR = PORT_TO_CLIENT_MAPPING[i]
			CLIENT_PORT_MAPPINGS[index].PORT_RANGE = PORT_TO_CLIENT_MAPPING[i]
			break
		}
	}

	if PR == nil {
		INFO(3, "CREATE_CLIENT_PORT_MAPPING >> ERROR >> unable to write to control socket >> ", err)
		return
		// if ROUTER != nil {
		//_, err := ROUTER.TCPControllerConnection.Write(ERRORBuffer[:])
		//if err != nil {
		// ROUTER.TCPControllerConnection.Close()
		// ROUTER.TCPControllerConnection = nil
		//}
		// }
	}

	if NSRequest.RouterPort == "" {
		NSRequest.RouterPort = "443"
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	ROUTERConn, err := dialer.Dial("tcp4", NSRequest.RouterIP+":"+NSRequest.RouterPort)
	if err != nil {
		INFO(3, "CREATE_CLIENT_PORT_MAPPING >> unable to dial router >> ", err)
		return
	}

	tmp := make([]byte, 3)
	tmp[0] = router.CODE_DeliveringUserSocket
	binary.BigEndian.PutUint16(tmp[1:], uint16(len(NSRequest.UUID)))
	_, err = ROUTERConn.Write(append(tmp, []byte(NSRequest.UUID)...))
	if err != nil {
		ERR(3, "unable to write nsrequest to router >> ", err)
		return
	}

	CLIENT_PORT_MAPPINGS[index].TunnelSocket = ROUTERConn

	// -------------------------------------------
	// -------------------------------------------
	//
	// EXIT NODE TO USER HANDSHAKE INITIALIZATION
	//
	// -------------------------------------------
	// -------------------------------------------
	CLIENT_PORT_MAPPINGS[index].ES, err = tcpcrypt.NewSocketWrapper(
		ROUTERConn,
		NSRequest.Type)
	if err != nil {
		INFO(3, "unable to create encrypted socket, ", err)
		return
	}

	err = CLIENT_PORT_MAPPINGS[index].ES.ReceiveHandshake()
	if err != nil {
		INFO(3, "unable to receive user handshake, ", err)
		return
	}

	// CLEAR OUT USEFULL DATA BEFORE REPLYING
	// fmt.Println("NSR:", NSRequest.InterfaceIP)
	// fmt.Println("NSR:", INTERFACE_IP)
	NSRequest.StartPort = PR.StartPort
	NSRequest.EndPort = PR.EndPort
	NSRequest.InterfaceIP = net.IP(INTERFACE_IP)
	NSRequest.RouterIP = ""
	NSRequest.RouterPort = ""
	// NSRequest.UUID = ""
	NSRequest.Type = 0

	outBytes, err := json.Marshal(NSRequest)
	if err != nil {
		INFO(3, "unable to marshal NSRequest, ", err)
		return
	}

	// outBuffer := make([]byte, math.MaxUint16)

	_, err = CLIENT_PORT_MAPPINGS[index].ES.Write(outBytes)
	if err != nil {
		INFO(3, "unable to response to NSRequest, ", err)
		return
	}

	// CLIENT_PORT_MAPPINGS[NSRequest.UUID].DataBuffer = xx[:]

	go ProcessUsersPackets(&SocketProcessorSignal{
		UUID: NSRequest.UUID,
	})

	go HandleClientTunnelSocket(&SocketProcessorSignal{
		UUID: NSRequest.UUID,
	})

	INFO(3, "++++++++++++++ REPLYING TO PORT ALLOCATION >> ", NSRequest.UUID)
}
