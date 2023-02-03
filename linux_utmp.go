//go:build linux
// +build linux

package logon

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	Empty        = 0x0
	RunLevel     = 0x1
	BootTime     = 0x2
	NewTime      = 0x3
	OldTime      = 0x4
	InitProcess  = 0x5
	LoginProcess = 0x6
	UserProcess  = 0x7
	DeadProcess  = 0x8
	Accounting   = 0x9
)

const (
	LineSize = 32
	NameSize = 32
	HostSize = 256
)

// utmp structures
// see man utmp
type ExitStatus struct {
	Termination int16
	Exit        int16
}

type TimeVal struct {
	Sec  int32
	Usec int32
}

type Utmp struct {
	Type int16
	// alignment
	_       [2]byte
	Pid     int32
	Device  [LineSize]byte
	Id      [4]byte
	User    [NameSize]byte
	Host    [HostSize]byte
	Exit    ExitStatus
	Session int32
	Time    TimeVal
	AddrV6  [16]byte
	// Reserved member
	Reserved [20]byte
}

// Addr returns the IPv4 or IPv6 address of the login record.
func (u *Utmp) Addr() net.IP {
	ip := make(net.IP, 16)
	// no error checking: reading from r.AddrV6 cannot fail
	binary.Read(bytes.NewReader(u.AddrV6[:]), binary.BigEndian, ip)
	if bytes.Equal(ip[4:], net.IPv6zero[4:]) {
		// IPv4 address, shorten the slice so that net.IP behaves correctly:
		ip = ip[:4]
	}
	return ip
}

func (u *Utmp) Event(class string) *Event {
	tv := time.Unix(int64(u.Time.Sec), 0)
	return &Event{
		RecordID: uint64(tv.Unix()),
		MinionID: xEnv.ID(),
		Inet:     xEnv.Inet(),
		Device:   string(u.Device[:trim(u.Device[:])]),
		Host:     string(u.Host[:trim(u.Host[:])]),
		User:     string(u.User[:trim(u.User[:])]),
		Addr:     u.Addr().String(),
		Time:     tv,
		Class:    class,
		Pid:      int(u.Pid),
		Typ:      strconv.Itoa(int(u.Type)),
	}
}

// read utmp
func readUtmp(file io.Reader) (*Utmp, error) {
	u := new(Utmp)

	err := binary.Read(file, binary.LittleEndian, u)
	if err != nil {
		return nil, err
	}

	return u, nil
}
