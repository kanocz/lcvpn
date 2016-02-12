package main

import (
	"flag"
	"log"

	"gopkg.in/gcfg.v1"
)

var config struct {
	Main struct {
		Port   int
		AesKey string
	}
	Remote map[string]*struct {
		ExtIP string
		LocIP string
	}
}

var (
	configfile = flag.String("config", "lcvpn.conf", "Config file")
)

func readConfig() {
	err := gcfg.ReadFileInto(&config, *configfile)
	if nil != err {
		log.Fatalf("Error reading config \"%s\" %s", *configfile, err)
	}
	if 0 == config.Main.Port {
		log.Fatalln("main.port is not set in config")
	}
	log.Printf("Config loaded: %+v\n", config)
}
