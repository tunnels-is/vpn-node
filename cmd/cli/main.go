package main

import (
	"flag"
	"runtime"
	"time"

	"github.com/tunnels-is/vpn-node/core"
	"github.com/tunnels-is/vpn-node/helpers"
	"github.com/tunnels-is/vpn-node/logging"
)

func main() {
	defer func() {
		helpers.BasicRecover()
		logging.Info("SLEEPING FOR 10 SECONDS BEFORE EXITING", nil)
		time.Sleep(10 * time.Second)
		logging.Info("NODE EXITED", nil)
	}()

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.StringVar(&core.RouterIP, "routerIP", "routerIP", "The node will fetch the config from this IP (optional)")

	flag.StringVar(&core.APIKey, "apiKey", "apiKey", "Device API key")
	flag.Parse()

	if core.APIKey == "" {
		core.C.APIKey = "00000000-0000-0000-0000-000000000000"
	}

	core.Start()
}
