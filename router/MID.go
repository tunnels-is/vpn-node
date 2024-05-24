package router

var BUFFER_pingPong = []byte{CODE_pingPong, 0, 0, 0, 0, 0, 0, 0, 0, 0}

const (
	CODE_pingPong                   = 101
	CODE_InitializingPortAllocation = 103
	CODE_DeliveringUserSocket       = 228
	CODE_ConnectingToControlSocket  = 229
)
