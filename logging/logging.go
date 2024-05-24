package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
)

var (
	LM         = LogMode(1)
	LogTarget  io.Writer
	JSONLogger *slog.Logger
	META       = map[string]interface{}{}
)

type LogMode int

const (
	NONE LogMode = iota
	STDOUT
	JSON
)

func init() {
	if LogTarget == nil {
		LogTarget = os.Stdout
	}
	JSONLogger = slog.New(slog.NewJSONHandler(LogTarget, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelDebug,
	}))
}

var Info = func(msg string, d map[string]interface{}) {
	fmt.Println(msg)
	fmt.Println(d)
}

var Warn = func(msg string, d map[string]interface{}) {
	fmt.Println(msg)
	fmt.Println(d)
}

var Error = func(msg string, err error, d map[string]interface{}) {
	fmt.Println(msg, "err:", err)
	fmt.Println(d)
}

var Admin = func(msg string, d map[string]interface{}) {
	fmt.Println(msg)
	fmt.Println(d)
}

var Debug = func(msg string, err any, stack bool, d map[string]interface{}) {
	fmt.Println(msg, "err:", err)
	fmt.Println(d)
	fmt.Println(string(debug.Stack()))
}

var INFO = func(_ int, d ...interface{}) {
	Info(fmt.Sprint(d...), nil)
}

var ERROR = func(_ int, d ...interface{}) {
	Error(fmt.Sprint(d...), nil, nil)
}

var ADMIN = func(_ int, d ...interface{}) {
	Admin(fmt.Sprint(d...), nil)
}
