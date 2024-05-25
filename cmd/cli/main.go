package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/tunnels-is/vpn-node/core"
	"github.com/tunnels-is/vpn-node/helpers"
	"github.com/tunnels-is/vpn-node/logging"
)

var (
	pass    string
	user    string
	remuser string
)

func main() {
	defer func() {
		helpers.BasicRecover()
		logging.Info("SLEEPING FOR 10 SECONDS BEFORE EXITING", nil)
		time.Sleep(1 * time.Second)
		logging.Info("NODE EXITED", nil)
	}()

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.StringVar(&core.NodeConfigPath, "config", "./files/vpn.json", "The node will fetch it's config from this location")
	flag.StringVar(&core.AuthConfigPath, "authConfig", "./files/auth.json", "path to authentication config")

	flag.StringVar(&pass, "pass", "", "use both -user and -pass to create a user+password in the -authConfig file")
	flag.StringVar(&user, "user", "", "use both -user and -pass to create a user+password in the -authConfig file")
	flag.StringVar(&remuser, "removeUser", "", "removes the specified user from -authConfig")
	flag.Parse()

	fmt.Println(pass, user, core.AuthConfigPath)
	if remuser != "" {
		helpers.RemoveUser(remuser, core.AuthConfigPath)
		os.Exit(1)
	}

	if pass != "" {
		if user == "" {
			panic("can not create a password without a -user")
		}
		if core.AuthConfigPath == "" {
			panic("-authConfig needs to be defined")
		}
		helpers.CreateNewUserAndPassword(user, pass, core.AuthConfigPath)
		os.Exit(1)
	}

	core.Start()
}
