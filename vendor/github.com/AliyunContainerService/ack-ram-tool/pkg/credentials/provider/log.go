package provider

import (
	"log"
	"os"
	"strings"
)

var debugMode bool

type Logger interface {
	Info(msg string)
	Debug(msg string)
	Error(err error, msg string)
}

var defaultLog Logger = &defaultLogger{}
var DefaultLogger = defaultLog.(*defaultLogger)

func init() {
	debugEnv := strings.Split(strings.ToLower(os.Getenv("DEBUG")), ",")
	for _, item := range debugEnv {
		if item == "sdk" || item == "tea" || item == "credentials-provider" {
			debugMode = true
			break
		}
	}
}

type defaultLogger struct {
	silentInfo bool
}

func (d *defaultLogger) SetSilentInfo(v bool) {
	d.silentInfo = v
}

func (d defaultLogger) DebugMode() bool {
	return debugMode
}

func (d defaultLogger) Info(msg string) {
	if d.silentInfo && !debugMode {
		return
	}
	log.Print(msg)
}

func (d defaultLogger) Debug(msg string) {
	if debugMode {
		log.Print(msg)
	}
}

func (d defaultLogger) Error(err error, msg string) {
	log.Print(msg)
}
