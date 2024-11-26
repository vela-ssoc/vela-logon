package logon

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/vela"
	"github.com/vela-ssoc/vela-kit/windows/evtx"
	"testing"
	"time"
)

func simpleEvtxWatcher(channel string, query string, withEvt func(evt *evtx.WinLogEvent) error) error {
	w, e := evtx.NewWatcher()
	if e != nil {
		return e
	}

	err := w.SubscribeFromBeginning(channel, query)
	if err != nil {
		return err
	}

	go func() {
		tk := time.NewTicker(time.Second)
		defer func() {
			tk.Stop()
			w.Shutdown()
		}()

		backoff := 0
		for {
			select {
			case evt := <-w.Event():
				withEvt(evt)
			case e := <-w.Error():
				fmt.Println(e.Error())
			case <-tk.C:
				backoff = backoff + 1
				if backoff > 30 {
					return
				}
			}
		}
	}()
	return nil
}

// TestWinLog01 测试windows下登录日志中额外数据字段的获取和处理
// ProcessLogonExdata函数
func TestWinLog01(t *testing.T) {
	withEvtTest01 := func(evt *evtx.WinLogEvent) error {
		ex, err := evt.EvData()
		if err != nil {
			t.Errorf(err.Error())
			return err
		}
		exdata := ProcessLogonExdata(&ex)
		exdataJson, _ := vela.JsonEncode(exdata)
		t.Log(string(exdataJson))
		return nil
	}
	err := simpleEvtxWatcher("Security", FailQuery, withEvtTest01)
	if err != nil {
		t.Errorf(err.Error())
	}
	time.Sleep(10 * time.Second)
}
