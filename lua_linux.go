//go:build linux
// +build linux

package logon

import (
	"github.com/vela-ssoc/vela-kit/lua"
)

/*
	local fail = vela.logon.fail()
	fail.pipe()
	fail.output()
	fail.start()
*/

func newLogonHelper(L *lua.LState, class string, path string) int {
	monitor := newMonitor(L, class, path)
	proc := L.NewVelaData(monitor.name, typeof)
	proc.Set(monitor)
	L.Push(proc)
	return 1
}

func newLogonFailL(L *lua.LState) int {
	return newLogonHelper(L, Fail, withFailFile())
}

func newLogonSuccessL(L *lua.LState) int {
	return newLogonHelper(L, SUCCESS, "/var/log/wtmp")
}

func newLogoutL(L *lua.LState) int {
	return 0
}

func newLogonL(L *lua.LState) int {
	return 0
}
