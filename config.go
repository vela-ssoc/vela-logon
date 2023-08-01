package logon

import (
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
)

type config struct {
	name   string
	class  string
	path   string   //linux logon record file
	bkt    []string //linux offset
	co     *lua.LState
	ignore *cond.Ignore
	filter *cond.Combine
	output lua.Writer
	pipe   *pipe.Chains
	ref    bool
}

func (cfg *config) handle(ev *Event) {
	if ev == nil {
		return
	}

	if cfg.ref {
		ev.ref()
	}

	if cfg.ignore.Match(ev) {
		return
	}

	if !cfg.filter.Match(ev) {
		return
	}

	if cfg.output != nil {
		cfg.output.Write(ev.Byte())
	}

	cfg.pipe.Do(ev, cfg.co, func(err error) {
		xEnv.Errorf("%s login Monitor pipe call fail %v", cfg.class, err)
	})
}

func (cfg *config) refL(L *lua.LState) int {
	cfg.ref = L.IsTrue(1)
	return 0
}

func (cfg *config) outputL(L *lua.LState) int {
	cfg.output = lua.CheckWriter(L.CheckVelaData(1))
	return 0
}

func (cfg *config) pipeL(L *lua.LState) int {
	cfg.pipe.CheckMany(L)
	return 0
}

func (cfg *config) filterL(L *lua.LState) int {
	cfg.filter.CheckMany(L)
	return 0
}

func (cfg *config) ignoreL(L *lua.LState) int {
	cfg.ignore.CheckMany(L)
	return 0
}

func (cfg *config) dbL(L *lua.LState) int {
	tab := auxlib.LToSS(L)
	if len(tab) == 0 {
		return 0
	}

	cfg.bkt = tab
	return 0
}

func (cfg *config) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "pipe":
		return lua.NewFunction(cfg.pipeL)
	case "ignore":
		return lua.NewFunction(cfg.ignoreL)
	case "filter":
		return lua.NewFunction(cfg.filterL)
	case "ref":
		return lua.NewFunction(cfg.refL)
	case "output":
		return lua.NewFunction(cfg.outputL)
	case "db":
		return lua.NewFunction(cfg.dbL)
	default:
		return lua.LNil
	}
}

func newConfig(L *lua.LState, class, path string) *config {
	return &config{
		path:   path,
		class:  class,
		ref:    true,
		co:     xEnv.Clone(L),
		pipe:   pipe.New(),
		ignore: cond.NewIgnore(),
		filter: cond.NewCombine(),
		bkt:    []string{"VELA_MONITOR_SEEK_DB", class},
	}
}
