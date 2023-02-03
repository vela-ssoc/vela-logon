package logon

import (
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/vela"
)

var xEnv vela.Environment

/*
	local f = vela.logon.fail()
	f.ignore("xxx")
	f.pipe()
	f.start()
*/

func call(L *lua.LState) int {
	return 0
}

func WithEnv(env vela.Environment) {
	xEnv = env
	tab := lua.NewUserKV()
	tab.Set("fail", lua.NewFunction(newLogonFailL))
	tab.Set("success", lua.NewFunction(newLogonSuccessL))
	tab.Set("logout", lua.NewFunction(newLogoutL))
	ex := lua.NewExport("vela.logon.export", lua.WithTable(tab), lua.WithFunc(call))
	xEnv.Set("logon", ex)
}
