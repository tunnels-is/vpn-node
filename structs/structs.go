package structs

import (
	"net"
	"sync"
	"time"

	"github.com/zveinn/tcpcrypt"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var RouterList [2000]*Router

type ROUTER_CORE struct {
	ListIndex int

	// KEEPING FOR REFACTOR
	Status            int
	Country           string
	Tag               string
	PublicIP          string
	Port              string
	AvailableMbps     int `json:"AvailableMbps"`
	AvailableUserMbps int `json:"AvailableUserMbps"`
	Online            bool
	LastPing          time.Time

	Slots    int
	Sessions int
}

type Router struct {
	ROUTER_CORE

	ConnectionAttempts      int
	TCPControllerConnection net.Conn
	// Online              bool

	ERS *tcpcrypt.SocketWrapper

	Nodes map[primitive.ObjectID]*Node
	Lock  sync.Mutex `json:"-" bson:"-"`
}

type NewNodeSocketAllocationRequest struct {
	UUID        string             `json:",omitempty"`
	Version     int                `json:"Version"`
	Type        tcpcrypt.EncType   `json:"Type"`
	RouterIP    string             `json:"RouterIP,omitempty"`
	RouterPort  string             `json:"RouterPort,omitempty"`
	InterfaceIP net.IP             `json:"InterfaceIP"`
	StartPort   uint16             `json:"StartPort"`
	EndPort     uint16             `json:"EndPort"`
	NodeID      primitive.ObjectID `json:"NodeID"`
}

type Node struct {
	ID      primitive.ObjectID `json:"_id,omitempty" bson:"_id"`
	Tag     string             `json:"Tag" bson:"Tag"`
	Admin   primitive.ObjectID `json:"Admin" bson:"Admin"`
	APIKey  string             `json:"APIKey" bson:"APIKey"`
	Status  int                `json:"Status" bson:"Status"`
	Updated time.Time          `json:"Updated" bson:"Updated"`
	Public  bool               `json:"Public" bson:"Public"`

	// ONLY APPLIES TO PUBLIC NODES
	// ListIndex int `json:"ListIndex" bson:"ListIndex"`

	TCPControllerConnection net.Conn                `json:"-" bson:"-"`
	ENS                     *tcpcrypt.SocketWrapper `json:"-" bson:"-"`
	LastOnline              time.Time               `json:"LastOnline" bson:"LastOnline"`
	ConnectedToRouter       time.Time               `json:"-" bson:"-"`
	LastPing                time.Time               `json:"-" bson:"-"`

	// Not used now but might be later
	Port string `json:"Port" bson:"Port"`
	// CONNECTION / NETWORK CONFIGURATIONS
	Country            string                   `json:"Country" bson:"Country"`
	InterfaceIP        string                   `json:"InterfaceIP" bson:"InterfaceIP"`
	RouterIndex        int                      `json:"RouterIndex" bson:"RouterIndex"`
	RouterIP           string                   `json:"RouterIP" bson:"RouterIP"`
	RouterPort         int                      `json:"RouterPort" bson:"RouterPort"`
	StartPort          int                      `json:"StartPort" bson:"StartPort"`
	EndPort            int                      `json:"EndPort" bson:"EndPort"`
	AvailableMbps      int                      `json:"AvailableMbps" bson:"AvailableMbps"`
	AvailableUserMbps  int                      `json:"AvailableUserMbps" bson:"AvailableUserMbps"`
	IP                 string                   `json:"IP" bson:"IP"`
	InternetAccess     bool                     `json:"InternetAccess" bson:"InternetAccess"`
	LocalNetworkAccess bool                     `json:"LocalNetworkAccess" bson:"LocalNetworkAccess"`
	Access             []*AP_DEVICE_USER_ACCESS `json:"Access" bson:"Access"`

	Slots    int `json:"Slots" bson:"Slots"`
	Sessions int
	Lock     *sync.Mutex `json:"-" bson:"-"`

	// STATS
	CPUUsage  byte `json:"CPUUsage" bson:"CPUUsage"`
	DiskUsage byte `json:"DiskUsage" bson:"DiskUsage"`
	MemUsage  byte `json:"MemUsage" bson:"MemUsage"`

	DNSAllowCustomOnly bool           `json:"DNSAllowCustomOnly"`
	DNS                []*NodeDNS     `json:"DNS"`
	Networks           []*NodeNetwork `json:"Networks"`
	EncryptionProtocol int            `json:"EncryptionProtocol"` // default 3 (AES256)
	DNSServers         []string       `json:"DNSServers"`
}
type NodeDNS struct {
	Domain   string   `json:"Domain" bson:"Domain"`
	Wildcard bool     `json:"Wildcard" bson:"Wildcard"`
	IP       []string `json:"IP" bson:"IP"`
	TXT      []string `json:"TXT" bson:"TXT"`
	CNAME    string   `json:"CNAME" bson:"CNAME"`
}
type NodeNetwork struct {
	Tag     string   `json:"Tag" bson:"Tag"`
	Network string   `json:"Network" bson:"Network"`
	Nat     string   `json:"Nat" bson:"Nat"`
	Routes  []*Route `json:"Routes" bson:"Routes"`
}

type NodeConnectRequest struct {
	APIKey string
}

type Route struct {
	Address string
	Metric  string
}

type GetNodeConfig struct {
	APIKey string
}

type AP_DEVICE_USER_ACCESS struct {
	UID primitive.ObjectID `json:"UID" bson:"UID"`
	Tag string             `json:"Tag" bson:"T"`
}
