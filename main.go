package main

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/zveinn/tcpcrypt"

	_ "net/http/pprof"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/tunnels-is/vpn-node/helpers"
	"github.com/tunnels-is/vpn-node/logging"
	"github.com/tunnels-is/vpn-node/router"
	"github.com/tunnels-is/vpn-node/structs"
)

func START_PPROF() {
	defer func() {
		if r := recover(); r != nil {
			log.Println(r, string(debug.Stack()))
		}
		RoutineWatcher <- 7
	}()

	http.ListenAndServe("0.0.0.0:63334", nil)
}

type ACCESS_POINT struct {
	UDPRouterConnection *net.UDPConn
	UDPRouterAddress    *net.UDPAddr
}

type TCPPacket struct {
	PACKET []byte
	FROM   net.IP
}

var (
	ERR   = logging.ERROR
	INFO  = logging.INFO
	ADMIN = logging.ADMIN

	LOG_INFO  = logging.Info
	LOG_WARN  = logging.Warn
	LOG_ERROR = logging.Error
	LOG_DEBUG = logging.Debug
	LOG_ADMIN = logging.Admin

	APIKey   string
	RouterIP string

	C                    = new(structs.Node)
	AR                   *structs.Router
	ControlSocketMonitor = make(chan byte, 100)

	// KILLTunnelsChan     = make(chan byte, 20)
	LastRouterSwitch    time.Time
	RouterSwitchTimeout float64 = 30

	InterfaceName       = "nvpn"
	InterfaceMTU        = 65535
	InterfaceTXQueueLen = 3000
	InterfaceMultiqueue = false

	TCPRWC io.ReadWriteCloser
	UDPRWC io.ReadWriteCloser

	KeepAliveIntervalSeconds float64 = 30
	RoutineWatcher                   = make(chan byte, 100)
	LastNodeIPListRefresh    time.Time
	RawPingBuffer            []byte
	KeepAliveBuffer          []byte
	SwitchingRoutersBuffer   []byte
	// PORTMAPPER_KILL          chan byte
	// PORTMAPPER_KILL_COMPLETE chan byte
	// PORTMAPPER_PANIC         chan byte
	INTERFACE_IP net.IP
	E            = elliptic.P521()
)

func GeneratePortAllocation() (err error) {
	C.Slots = C.AvailableMbps / C.AvailableUserMbps
	portPerUser := (C.EndPort - C.StartPort) / C.Slots

	defer func() {
		helpers.BasicRecover()
		if err != nil {
			LOG_ERROR("port allocations", err, map[string]interface{}{
				"startPort":   C.StartPort,
				"endPort":     C.EndPort,
				"slots":       C.Slots,
				"portPerUser": portPerUser,
			})
		}
	}()

	currentPort := uint16(C.StartPort)

	LOG_DEBUG("port allocations", nil, false, map[string]interface{}{
		"startPort":   C.StartPort,
		"endPort":     C.EndPort,
		"slots":       C.Slots,
		"portPerUser": portPerUser,
	})

	for uc := 0; uc < C.Slots; uc++ {
		PR := new(PORT_RANGE)
		PR.StartPort = uint16(currentPort)
		PR.EndPort = PR.StartPort + uint16(portPerUser)

		// log.Println("ASSIGNING PORTS: ", PR.StartPort, " >> ", PR.EndPort)
		for i := PR.StartPort; i <= PR.EndPort; i++ {

			if i < PR.StartPort {
				return errors.New("start port is too small")
			} else if i > PR.EndPort {
				return errors.New("end port is too big")
			}

			if PORT_TO_CLIENT_MAPPING[i] != nil {
				if PORT_TO_CLIENT_MAPPING[i].StartPort < PR.StartPort {
					return errors.New("start port is too small")
				}
				if PORT_TO_CLIENT_MAPPING[i].StartPort < PR.EndPort {
					return errors.New("end port is too big")
				}
			}

			PORT_TO_CLIENT_MAPPING[i] = PR
		}

		currentPort = PR.EndPort + 1
	}

	// for _, pm := range PORT_TO_CLIENT_MAPPING {
	// 	if pm != nil {
	// 		log.Println(pm.StartPort, pm.EndPort)
	// 	}
	// }

	return nil
}

// var AVAILABLE_PORTS []*PORT_RANGE
var (
	CLIENT_PORT_MAPPINGS   [10000]*CLIENT_PORT_MAPPING
	CLIENT_LOCK            = sync.Mutex{}
	PORT_TO_CLIENT_MAPPING [math.MaxUint16]*PORT_RANGE
)

type PORT_RANGE struct {
	StartPort uint16
	EndPort   uint16
	Client    *CLIENT_PORT_MAPPING
}

//type PACKET struct {
//	// Length int
//	Data []byte
//}

type CLIENT_PORT_MAPPING struct {
	UUID       string
	Version    int
	PORT_RANGE *PORT_RANGE
	// TCP          chan []byte
	// UDP          chan []byte
	Packets            chan []byte
	TunnelSocket       net.Conn
	DataBuffer         []byte
	LastPingFromClient time.Time
	ES                 *tcpcrypt.SocketWrapper
	// OTK          structs.OTK
}

var (
	PACKET_PROCESSOR_MONITOR = make(chan *SocketProcessorSignal, 300)
	TUNNEL_PROCESSOR_MONITOR = make(chan *SocketProcessorSignal, 300)
)

type SocketProcessorSignal struct {
	UUID string
}

func main() {
	defer func() {
		helpers.BasicRecover()
		LOG_INFO("SLEEPING FOR 10 SECONDS BEFORE EXITING", nil)
		time.Sleep(10 * time.Second)
		LOG_INFO("NODE EXITED", nil)
	}()

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.StringVar(&RouterIP, "routerIP", "routerIP", "The node will fetch the config from this IP (optional)")

	flag.StringVar(&APIKey, "apiKey", "apiKey", "Device API key")
	flag.Parse()

	if APIKey == "" {
		C.APIKey = "00000000-0000-0000-0000-000000000000"
	}

	if RouterIP == "" {
		for _, v := range structs.RouterList {
			if v == nil {
				continue
			}

			config, err := GetNodeConfig(v.PublicIP)
			if err != nil {
				time.Sleep(1 * time.Second)
			} else {
				C = config
				break
			}
		}
	} else {
		config, err := GetNodeConfig(RouterIP)
		if err != nil {
			time.Sleep(1 * time.Second)
		} else {
			C = config
		}
	}

	logging.META["ID"] = C.ID.Hex()
	logging.META["TAG"] = C.Tag
	logging.META["RIP"] = C.RouterIP

	err := GeneratePortAllocation()
	if err != nil {
		os.Exit(1)
	}

	INTERFACE_IP = net.ParseIP(C.InterfaceIP)
	if INTERFACE_IP == nil {
		LOG_ERROR(
			"Interface ip is invalid",
			nil,
			map[string]interface{}{"interfaceIP": C.InterfaceIP},
		)
		os.Exit(1)
	}
	INTERFACE_IP = INTERFACE_IP.To4()

	CREATE_ACTIVE_ROUTER(C.RouterIP)

	RoutineWatcher <- 1
	RoutineWatcher <- 2
	RoutineWatcher <- 3
	RoutineWatcher <- 4
	RoutineWatcher <- 5
	RoutineWatcher <- 7

	// raw socket reader
	RoutineWatcher <- 6
	RoutineWatcher <- 17

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-quit:
			LOG_INFO("quit signal received", nil)
			os.Exit(1)

		case P := <-TUNNEL_PROCESSOR_MONITOR:
			go HandleClientTunnelSocket(P)

		case P := <-PACKET_PROCESSOR_MONITOR:
			go ProcessUsersPackets(P)

		case ID := <-RoutineWatcher:
			LOG_INFO(
				"routine watched trigger",
				map[string]interface{}{"id": ID},
			)
			switch ID {
			case 1:
				go PingActiveController()
			case 2:
				go PingActiveClients()
			case 3:
			case 4:
				go InitializeRouterControlSocket()
			case 5:
			case 6:
				go ReadFromRawTCPSocket()
			case 17:
				go ReadFromRawUDPSocket()
			default:
				LOG_INFO(
					"unknown ID in RoutineWatcher",
					map[string]interface{}{"id": ID},
				)
			}

		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func PingActiveClients() {
	var err error
	defer func() {
		helpers.BasicRecover()

		if err != nil {
			LOG_ERROR(
				"active client ping routine closing",
				err,
				map[string]interface{}{
					"publicIP":   AR.PublicIP,
					"routerPort": C.RouterPort,
				},
			)
		}

		RoutineWatcher <- 2
	}()

	for {
		time.Sleep(10 * time.Second)

		for i := range CLIENT_PORT_MAPPINGS {
			if CLIENT_PORT_MAPPINGS[i] == nil {
				continue
			}
			// fmt.Println("VERSION:", CLIENT_PORT_MAPPINGS[i].Version)
			if time.Since(CLIENT_PORT_MAPPINGS[i].LastPingFromClient).Minutes() > 5 {
				NukeClient(CLIENT_PORT_MAPPINGS[i])
				continue
			}
			select {
			case CLIENT_PORT_MAPPINGS[i].Packets <- router.BUFFER_pingPong:
			default:
			}
		}
	}
}

func PingActiveController() {
	var err error
	defer func() {
		helpers.BasicRecover()

		if err != nil {
			LOG_ERROR(
				"active router ping routine closing",
				err,
				map[string]interface{}{
					"publicIP":   AR.PublicIP,
					"routerPort": C.RouterPort,
				},
			)
		}

		RoutineWatcher <- 1
	}()

	for {
		populatePingBufferWithStats()
		time.Sleep(9 * time.Second)

		if AR != nil && AR.ERS != nil {

			LOG_INFO("ping buffer", map[string]interface{}{
				"ping": router.BUFFER_pingPong,
			})

			_, err = AR.ERS.Write(router.BUFFER_pingPong)
			if err != nil {
				AR.ERS.SOCKET.Close()
				return
			}
		}
	}
}

func populatePingBufferWithStats() {
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		ERR(3, "Unable to get cpu percent", err)
		return
	}
	router.BUFFER_pingPong[1] = byte(int(cpuPercent[0]))

	memStats, err := mem.VirtualMemory()
	if err != nil {
		ERR(3, "Unable to get mem stats", err)
		return

	}
	router.BUFFER_pingPong[2] = byte(int(memStats.UsedPercent))

	diskUsage, err := disk.Usage("/")
	if err != nil {
		ERR(3, "Unable to get disk usage", err)
		return
	}
	router.BUFFER_pingPong[3] = byte(int(diskUsage.UsedPercent))

	router.BUFFER_pingPong[4] = 255
	router.BUFFER_pingPong[5] = 255
}

func CREATE_ACTIVE_ROUTER(IP string) {
	AR = new(structs.Router)
	AR.PublicIP = IP
	AR.Port = strconv.Itoa(C.RouterPort)
	AR.LastPing = time.Now()
}

func GetUpdatedDeviceConfig() {
	defer func() {
		if r := recover(); r != nil {
			INFO(3, r, string(debug.Stack()))
		}
		RoutineWatcher <- 1
	}()

	for {
		time.Sleep(60 * time.Second)

		if AR == nil {
			ERR(3, "Unable to get updated device config. No active router set")
			continue
		}

		config, err := GetNodeConfig(AR.PublicIP)
		if err != nil {
			continue
		}

		// Check if we need a reboot
		needsReboot := false
		if C.AvailableMbps != config.AvailableMbps {
			needsReboot = true
		}
		if C.AvailableUserMbps != config.AvailableUserMbps {
			needsReboot = true
		}
		if C.InterfaceIP != config.InterfaceIP {
			needsReboot = true
		}
		if C.RouterIP != config.RouterIP {
			needsReboot = true
		}
		if C.StartPort != config.StartPort {
			needsReboot = true
		}
		if C.EndPort != config.EndPort {
			needsReboot = true
		}
		if C.RouterPort != config.RouterPort {
			needsReboot = true
		}

		if needsReboot {
			os.Exit(1)
		} else {
			C = config
			// apply new blocklist
		}

	}
}

func GetNodeConfig(IP string) (C *structs.Node, err error) {
	log.Println("Fetching config from: ", IP)

	C = new(structs.Node)
	DF := new(structs.GetNodeConfig)
	DF.APIKey = APIKey

	err, resp, code := helpers.SendRequestToController(
		IP,
		"443",
		"POST",
		"v3/node/config",
		DF,
		5000,
		true,
	)
	if err != nil || code != 200 {
		LOG_ERROR(
			"unable to get node config",
			err,
			map[string]interface{}{"respcode": code},
		)
		if err == nil {
			return nil, errors.New("")
		}
		return
	}

	err = json.Unmarshal(resp, &C)
	if err != nil {
		LOG_ERROR(
			"unable to marshal node config",
			err,
			map[string]interface{}{"respcode": code},
		)
		return nil, err
	}

	LOG_DEBUG(
		"Got node config",
		nil,
		true,
		map[string]interface{}{"config": C},
	)

	return
}

// func GET_MEM() {
// 	S.MEMStats, _ = mem.VirtualMemory()
// }

// func SCRAPE_SYSTEM_STATS() {
// 	GET_MEM()
// 	cp, _ := cpu.Info()
// 	S.CPUStats = &cp[0]
// 	S.CPUCoreCount = 0
// 	for _, v := range cp {
// 		S.CPUCoreCount += v.Cores
// 	}
// 	S.HOSTStats, _ = host.Info()
// 	// S.HOSTStats.HostID = strings.Replace(S.HOSTStats.HostID, "-", "", -1)
// }

// func create_info_buffer() (infoBytes []byte) {
// 	SCRAPE_SYSTEM_STATS()
// 	infoBytes = make([]byte, 0)
// 	// log.Println(S.HOSTStats.HostID)   // 32 bytes
// 	log.Println(S.HOSTStats.BootTime) // 8 bytes
// 	log.Println(S.MEMStats.Free)      // 8 bytes
// 	log.Println(S.CPUStats.Cores)     // 4 bytes

// 	HID := [32]byte{}
// 	infoBytes = append(infoBytes, HID[:]...) // 0-31
// 	infoBytes = append(infoBytes, make([]byte, 20)...)
// 	binary.BigEndian.PutUint64(infoBytes[32:40], S.HOSTStats.Uptime)             // 32-39
// 	binary.BigEndian.PutUint64(infoBytes[40:48], uint64(S.MEMStats.UsedPercent)) // 40-47
// 	binary.BigEndian.PutUint32(infoBytes[48:52], uint32(S.CPUCoreCount))         // 48-51

// 	return
// }

// func REFRESH_ROUTER_LIST(oneTimeOnly bool) (err error) {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			log.Println(r, string(debug.Stack()))
// 		}

// 		if !oneTimeOnly {
// 			time.Sleep(60 * time.Second)
// 			RoutineWatcher <- 1
// 		}
// 	}()

// 	LastNodeIPListRefresh = time.Now()

// 	ipList, err := CloudFlareResolver.LookupHost(context.Background(), C.DefaultRouterLookupDomain)
// 	if err != nil {
// 		log.Println(err)
// 		ipList, err = GoogleResolver.LookupHost(context.Background(), C.DefaultRouterLookupDomain)
// 		// ipList, err = net.LookupIP(C.DefaultRouterLookupDomain)
// 		if err != nil {
// 			log.Println("@@@@@@@@@@@@@@@@@@ COULD NOT GET ROUTER LIST", err)
// 			time.Sleep(10 * time.Second)
// 			return
// 		}
// 	}

// 	var already_in_list bool
// 	var R *structs.AP_ROUTER
// 	var addedCount int
// 	for _, v := range ipList {
// 		already_in_list = false
// 		for i := range RouterList {
// 			if RouterList[i] == nil {
// 				continue
// 			}
// 			if RouterList[i].PublicIP == v {
// 				already_in_list = true
// 			}
// 		}

// 		if !already_in_list {
// 			log.Println("NEW IP:", v)
// 			R = new(structs.AP_ROUTER)
// 			R.PublicIP = v
// 			R.Port = strconv.Itoa(C.DefaultRouterPort)
// 			// N.KillChan = make(chan byte, 10)
// 			R.MS = defaultMS
// 			R.LastPing = time.Now()
// 			R.TimeoutForSeconds = 0
// 			R.REGISTERED = false
// 			R.OK_TO_USE = false

// 			for i := 0; i < len(RouterList); i++ {
// 				if RouterList[i] == nil {
// 					RouterList[i] = R
// 					addedCount++
// 					break
// 				}
// 			}

// 		}
// 	}

// 	log.Println("TOTAL ROUTERS ADDED:", addedCount)
// 	return nil
// }

//func HandleData(buf []byte, numRead int) {
//	// var flow gopacket.Flow
//
//	packet1 := gopacket.NewPacket(buf[:numRead], layers.LayerTypeIPv4, gopacket.Default)
//	trans := packet1.TransportLayer()
//	// log.Println(trans.TransportFlow().Src().String())
//	if trans != nil {
//		// log.Println(trans.TransportFlow())
//		// flow = trans.TransportFlow()
//		// P := flow.Src().String()
//		if trans.TransportFlow().Src().String() == "53" {
//			// }
//			// if P == "53" {
//			log.Println("========= REPLY ============\n", packet1, "\n", "\n=====================================")
//			// if CURR_SOCK != nil {
//			// 	CURR_SOCK.Write(buf[:numRead])
//			// }
//		}
//	}
//}

//func RELEASE_PORTS() {
//	defer func() {
//		if r := recover(); r != nil {
//			log.Println(r, string(debug.Stack()))
//		}
//		RoutineWatcher <- 6
//	}()
//
//	WO := new(graph.AP_WalkObject)
//	WO.Tag = "RELEASE_PORT"
//	WO.TimeThreshold = 1000
//	WO.Action = func(WO *graph.AP_WalkObject, e6 *graph.E6) {
//		// if I != nil {
//		// 	if time.Since(I.LastActivity).Seconds() > 120 {
//		// 		// log.Println("  ------------ RELEASING MAPPING FOR PORT:", e6.I)
//		// 		// M = nil
//		// 		// I = nil
//		// 	}
//		// }
//	}
//
//	for {
//		time.Sleep(2 * time.Second)
//		graph.AP_NEW_WALK(WO)
//	}
//}
//
//func GENERAL_VALIDATION_AND_NOTIFICATIONS() {
//	// log.Println("===================")
//	// log.Println("===================")
//	// log.Println("DEFAULT UDP CONNECTION TIMEOUT: ", C.UDPTimeoutInSeconds)
//	// log.Println("DEFAULT BANDWITH PER CLIENT (Mbps): ", C.CLIENTS.MAXBandwidthPerClientInMbps)
//	// log.Println("DEFAULT ROUTER LOOKUP DOMAIN: ", C.DefaultRouterLookupDomain)
//	// log.Println("DEFAULT UDP ROUTER PORT: ", C.DefaultRouterPort)
//	// log.Println("===================")
//	// log.Println("===================")
//	// log.Println("===================")
//}

// func GENERATE_AVAILABLE_USER_PORTS() {

// 	var tunnelEndPort = C.UDPTunnelStartPort + 10
// 	for i := 0; i < math.MaxUint16; i++ {
// 		if i < int(C.CLIENTS.StartPort) {
// 			C.CLIENTS.AvailableClientPorts[uint16(i)] = false
// 			continue
// 		}

// 		if i >= C.UDPTunnelStartPort && i <= tunnelEndPort {
// 			C.CLIENTS.AvailableClientPorts[uint16(i)] = false
// 			continue
// 		}

// 		if i == C.DefaultRouterPort {
// 			C.CLIENTS.AvailableClientPorts[uint16(i)] = false
// 			continue
// 		}

// 		C.CLIENTS.AvailableClientPorts[uint16(i)] = true
// 	}
// }

// func GENERATE_PORT_SLOTS_v3() {

// 	structs.AP_PM.AllocationChannel = make(chan *structs.AP_PORT_SLOT, 100000)

// 	var totalClientsInt int = int(C.CLIENTS.TotalClients)
// 	var portsPerClientInt int = int(C.CLIENTS.PortPerClient)

// 	for i := 0; i < totalClientsInt; i++ {
// 		newSlot := new(structs.AP_PORT_SLOT)
// 		// newSlot.StartPort = uint16(currentPort)
// 		// newSlot.EndPort = newSlot.StartPort + uint16(C.CLIENTS.PortPerClient) - 1 // -1 to represent the actual index numbers and not a count
// 		var allocatedPorts int = 0
// 		for ii := range C.CLIENTS.AvailableClientPorts {
// 			if !C.CLIENTS.AvailableClientPorts[ii] {
// 				continue
// 			}
// 			newSlot.Ports = append(newSlot.Ports, uint16(ii))
// 			structs.AP_PORT_TO_SLOTS[ii] = newSlot

// 			go LAUNCH_CLIENT_UDP_INGRESS_LISTENER(strconv.Itoa(ii))
// 			C.CLIENTS.AvailableClientPorts[ii] = false
// 			// newSlot.MappablePorts[ii] = new(structs.PORT_MAPPING)
// 			// newSlot.MappablePorts[ii].Available = true
// 			// newSlot.MappablePorts[ii].PORT = uint16(ii)

// 			// currentPort++
// 			allocatedPorts++
// 			if allocatedPorts == portsPerClientInt {
// 				break
// 			}
// 		}

// 		// log.Println("ALLOCATING SLOT", i, ">> PORTS >>", newSlot.Ports)
// 		structs.AP_PM.Slots = append(structs.AP_PM.Slots, newSlot)
// 		structs.AP_PM.AllocationChannel <- newSlot
// 	}
// }

// func PROCESS_TIMEOUTS() {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			log.Println(r, string(debug.Stack()))
// 		}
// 		RoutineWatcher <- 7
// 	}()

// 	for i := range structs.AP_PM.Slots {
// 		slot := structs.AP_PM.Slots[i]
// 		var mostInactivePortTimer float64 = 0
// 		var mostInactiveIndex int = 0

// 		for ii := range slot.MappablePorts {
// 			if slot.MappablePorts[ii] == nil {
// 				continue
// 			}

// 			timeLeft := time.Since(slot.MappablePorts[ii].LastActivity).Seconds()
// 			if timeLeft > 130 {
// 				slot.PortAllocationLock.Lock()
// 				slot.SourcePorts[slot.MappablePorts[ii].SOURCE] = nil
// 				slot.MappablePorts[ii].Available = true
// 				slot.PortAllocationLock.Unlock()
// 				continue
// 			}

// 			if timeLeft > mostInactivePortTimer {
// 				mostInactivePortTimer = timeLeft
// 				mostInactiveIndex = ii
// 			}

// 		}

// 		slot.MappablePortWithOldestTime = uint16(mostInactiveIndex)

// 	}
// }
