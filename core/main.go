package core

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
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
	INTERFACE_IP             net.IP
	E                        = elliptic.P521()
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

	return nil
}

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

func Start() {
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
