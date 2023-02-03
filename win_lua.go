//go:build windows
// +build windows

package logon

import (
	"github.com/vela-ssoc/vela-kit/lua"
)

const (
	//"*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= 2592000000]]]
	//query "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= 3600000]]]

	SuccessQuery = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 10368000000]]]"
	FailQuery    = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 10368000000]]]"
	LogoutQuery  = "*[System[(EventID=4634) and TimeCreated[timediff(@SystemTime) <= 10368000000]]]"
)

func helpL(L *lua.LState, class, query string) int {
	m := newMonitor(L, class, query)
	proc := L.NewVelaData(m.Name(), typeof)
	proc.Set(m)
	L.Push(proc)
	return 1
}

func newLogonFailL(L *lua.LState) int {
	return helpL(L, Fail, FailQuery)
}
func newLogonSuccessL(L *lua.LState) int {
	return helpL(L, SUCCESS, SuccessQuery)
}

func newLogoutL(L *lua.LState) int {
	return helpL(L, Logout, LogoutQuery)
}
func newLogonL(L *lua.LState) int {
	return 0
}
