// Package kmsg provides a minimal interface for dealing with
// kmsg messages extracted from `/dev/kmesg`.
package kmsg

import (
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type Priority uint8

const (
	PriorityEmerg Priority = iota
	PriorityAlert
	PriorityCrit
	PriorityErr
	PriorityWarning
	PriorityNotice
	PriorityInfo
	PriorityDebug
)

func (p Priority) String() (s string) {
	switch p {
	case PriorityEmerg:
		s = "emerg"
	case PriorityAlert:
		s = "alert"
	case PriorityCrit:
		s = "crit"
	case PriorityErr:
		s = "err"
	case PriorityWarning:
		s = "warning"
	case PriorityNotice:
		s = "notice"
	case PriorityInfo:
		s = "info"
	case PriorityDebug:
		s = "debug"
	default:
		s = "unknown"

	}

	return
}

type Facility uint8

const (
	FacilityKern Facility = iota
	FacilityUser
	FacilityMail
	FacilityDaemon
	FacilityAuth
	FacilitySyslog
	FacilityLpr
	FacilityNews

	FacilityUnknown // custom facility used to delimite those that we know
)

func (f Facility) String() (s string) {
	switch f {
	case FacilityKern:
		s = "kern"
	case FacilityUser:
		s = "user"
	case FacilityMail:
		s = "mail"
	case FacilityDaemon:
		s = "daemon"
	case FacilityAuth:
		s = "auth"
	case FacilitySyslog:
		s = "syslog"
	case FacilityLpr:
		s = "lpr"
	case FacilityNews:
		s = "news"
	default:
		s = "unknown"
	}

	return
}

type Flag byte

const (
	FlagUnknown Flag = iota

	FlagDefault           // -: default flag
	FlagFragment          // c: indicates the fragment of a line
	FlagFragmentFollowing // +: continuation of a fragment

)

// DecodeFlag decodes the raw byte flag into a type Flag object.
func DecodeFlag(rawFlag byte) (flag Flag) {
	switch rawFlag {
	case '-':
		flag = FlagDefault
	case 'c':
		flag = FlagFragment
	case '+':
		flag = FlagFragmentFollowing
	default:
		flag = FlagUnknown
	}

	return
}

func IsValidFacility(facility uint8) (isValid bool) {
	isValid = (facility < uint8(FacilityUnknown))
	return
}

type Message struct {
	Facility       Facility
	Flag           Flag
	Message        string
	Priority       Priority
	SequenceNumber int64
	Timestamp      time.Time
}

// DecodePrefix extracts both priority and facility from a given
// syslog(2) encoded prefix.
//
//	   facility    priority
//      .-----------.  .-----.
//      |           |  |     |
//	7  6  5  4  3  2  1  0    bits
//
// ps.: the priority does not need to be verified because we're
//      picking the first 3 bits and there's no way of having a
//	wrong priority given that the set of possible values has
//	8 numbers.
func DecodePrefix(prefix uint8) (priority Priority, facility Facility) {
	const priortyMask uint8 = (1 << 3) - 1

	facilityNum := prefix >> 3

	if !IsValidFacility(facilityNum) {
		facility = FacilityUnknown
	} else {
		facility = Facility(facilityNum)
	}

	priority = Priority(prefix & priortyMask)

	return
}

// Parse takes care of parsing a `kmsg` message acording to the kernel
// documentation at https://www.kernel.org/doc/Documentation/ABI/testing/dev-kmsg.
//
// REGULAR MESSAGE:
//
//                  INFO		              MSG
//     .------------------------------------------. .------.
//    |                                            |        |
//    |	int	int      int      char, <ignore>   | string |
//    prefix  , seq, timestamp_us,flag[,..........];<message>
//
//
// CONTINUATION:
//
//	    | key | value |
//	/x7F<THIS>=<THATTT>
//
func Parse(rawMsg string) (m *Message, err error) {
	if rawMsg == "" {
		err = errors.Errorf("msg must not be empty")
		return
	}

	splittedMessage := strings.SplitN(rawMsg, ";", 2)
	if len(splittedMessage) < 2 {
		err = errors.Errorf("message field not present")
		return
	}

	m = new(Message)

	infoSection := splittedMessage[0]
	m.Message = strings.TrimSpace(splittedMessage[1])

	splittedInfoSection := strings.SplitN(infoSection, ",", 5)
	if len(splittedInfoSection) < 4 {
		err = errors.Errorf("info section with not enought fields")
		return
	}

	prefix, err := strconv.ParseInt(splittedInfoSection[0], 10, 8)
	if err != nil {
		err = errors.Wrapf(err,
			"couldn't convert priority to int")
		return
	}

	m.Priority, m.Facility = DecodePrefix(uint8(prefix))

	m.SequenceNumber, err = strconv.ParseInt(splittedInfoSection[1], 10, 64)
	if err != nil {
		err = errors.Wrapf(err,
			"couldn't convert sequence number to int64")
		return
	}

	timestamp, err := strconv.ParseInt(splittedInfoSection[2], 10, 64)
	if err != nil {
		err = errors.Wrapf(err,
			"couldn't convert sequence number to int64")
		return
	}

	m.Timestamp = time.Unix(timestamp/int64(time.Millisecond), 0)

	if len(splittedInfoSection[3]) != 1 {
		err = errors.Errorf("flag must be a single char")
		return
	}

	m.Flag = DecodeFlag(splittedInfoSection[3][0])

	return
}
