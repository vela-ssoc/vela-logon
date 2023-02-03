package logon

import (
	"bytes"
	"fmt"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"os"
	"time"
)

var monToNum = map[string]string{
	"Jan": "01",
	"Feb": "02",
	"Mar": "03",
	"Apr": "04",
	"May": "05",
	"Jun": "06",
	"Jul": "07",
	"Aug": "08",
	"Sep": "09",
	"Oct": "10",
	"Nov": "11",
	"Dec": "12",
}

func Convert2Pid(v []byte) (string, int) {
	if !bytes.HasPrefix(v, []byte("sshd[")) {
		return "sshd", -1
	}

	size := len(v)
	pid, e := auxlib.ToIntE(string(v[5 : size-2]))
	if e != nil {
		return "sshd", -1
	}

	return "sshd", pid
}

// 2022 Sep 30 17:58:01

func Convert2Time(mon, day, hms []byte) time.Time {
	now := time.Now()
	m, ok := monToNum[string(mon)]
	if !ok {
		return now
	}

	s := fmt.Sprintf("%d-%s-%s %s", now.Year(), m, string(day), string(hms))
	tv, err := time.Parse("2006-01-02 15:04:05", s)

	if err != nil {
		return now
	}
	return tv
}

func withFailFile() string {
	_, err := os.Stat("/var/log/btmp")
	if err == nil {
		return "/var/log/btmp"
	}

	return "/var/log/secure"
}

// get byte \0 index
func trim(byteArray []byte) int {
	n := bytes.IndexByte(byteArray[:], 0)
	if n == -1 {
		return 0
	}

	return n
}
