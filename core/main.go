package core

import (
	"crypto/elliptic"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
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

var (
	ERR   = logging.ERROR
	INFO  = logging.INFO
	ADMIN = logging.ADMIN

	LOG_INFO  = logging.Info
	LOG_WARN  = logging.Warn
	LOG_ERROR = logging.Error
	LOG_DEBUG = logging.Debug
	LOG_ADMIN = logging.Admin

	NodeConfigPath string
	AuthConfigPath string

	Auth map[string]string
	C    = new(structs.Node)
	// AR                   *structs.Router
	ControlSocketMonitor = make(chan byte, 100)

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

	LOG_INFO("port allocations", map[string]interface{}{
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
	UUID string
	// Version    int
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
	var err error
	Auth = helpers.ReadAuthConfig(AuthConfigPath)
	C = helpers.ReadNodeConfig(NodeConfigPath)

	logging.META["ID"] = C.ID.Hex()
	logging.META["TAG"] = C.Tag
	logging.META["RIP"] = C.RouterIP

	err = GeneratePortAllocation()
	if err != nil {
		os.Exit(1)
	}

	if C.StartPort <= C.Port && C.Port <= C.EndPort {
		panic("Port can not be between StartPort and EndPort")
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

	RoutineWatcher <- 1
	RoutineWatcher <- 2
	RoutineWatcher <- 3
	RoutineWatcher <- 4
	RoutineWatcher <- 5
	RoutineWatcher <- 6
	RoutineWatcher <- 7

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
				go UpdateConfigs()
			case 2:
				go PingActiveClients()
			case 3:
				go StartTCPControlListener()
			case 4:
				go StartUDPControlListener()
				// go InitializeRouterControlSocket()
			case 5:
			case 6:
				go ReadFromRawTCPSocket()
			case 7:
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
				nil,
			)
		}

		RoutineWatcher <- 2
	}()

	for {
		time.Sleep(10 * time.Second)
		populatePingBufferWithStats()

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

func UpdateConfigs() {
	defer func() {
		if r := recover(); r != nil {
			INFO(3, r, string(debug.Stack()))
		}
		RoutineWatcher <- 1
	}()

	for {
		time.Sleep(30 * time.Second)
		out := helpers.ReadNodeConfig(NodeConfigPath)
		if out != nil {
			C = out
		}
		outA := helpers.ReadAuthConfig(AuthConfigPath)
		if outA != nil {
			Auth = outA
		}
	}
}
