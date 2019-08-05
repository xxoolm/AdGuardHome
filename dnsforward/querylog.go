package dnsforward

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/AdguardTeam/golibs/log"
	bolt "github.com/etcd-io/bbolt"
	"github.com/miekg/dns"
)

const (
	logBufferCap           = 100       // maximum capacity of logBuffer before it's flushed to disk
	queryLogRotationPeriod = time.Hour // time period to execute the procedure to delete expired items
	queryLogFileName       = "querylog.db"
	queryLogSize           = 5000 // maximum API response for /querylog
	queryLogTopSize        = 500  // Keep in memory only top N values
)

// queryLog is a structure that writes and reads the DNS query log
type queryLog struct {
	timeLimit  uint    // how far in the past we care about querylogs (in hours)
	logFile    string  // path to the log file
	runningTop *dayTop // current top charts
	db         *bolt.DB
	dbLock     sync.Mutex

	logBufferLock sync.RWMutex
	logBuffer     []*logEntry
	fileFlushLock sync.Mutex // synchronize a file-flushing goroutine and main thread
	flushPending  bool       // don't start another goroutine while the previous one is still running
}

func (l *queryLog) dbOpen() {
	var err error
	l.db, err = bolt.Open(l.logFile, 0644, nil)
	if err != nil {
		log.Error("bolt.Open: %s", err)
	}
}

func (l *queryLog) dbReopen() {
	l.dbLock.Lock()
	if l.db != nil {
		l.db.Close()
	}

	var err error
	l.db, err = bolt.Open(l.logFile, 0644, nil)
	if err != nil {
		log.Error("bolt.Open: %s", err)
	}
	l.dbLock.Unlock()
}

func (l *queryLog) dbBeginTxn() *bolt.Tx {
	l.dbLock.Lock()
	defer l.dbLock.Unlock()
	if l.db == nil {
		return nil
	}
	tx, err := l.db.Begin(true)
	if err != nil {
		log.Error("db.Begin: %s", err)
		return nil
	}
	return tx
}

// newQueryLog creates a new instance of the query log
// noDB: if TRUE, don't open/create database file
func newQueryLog(baseDir string, noDB bool) *queryLog {
	l := &queryLog{
		logFile:    filepath.Join(baseDir, queryLogFileName),
		runningTop: &dayTop{},
	}

	if !noDB {
		l.dbOpen()
	}
	return l
}

type logEntry struct {
	Question []byte
	Answer   []byte `json:",omitempty"` // sometimes empty answers happen like binerdunt.top or rev2.globalrootservers.net
	Result   dnsfilter.Result
	Time     time.Time
	Elapsed  time.Duration
	IP       string
	Upstream string `json:",omitempty"` // if empty, means it was cached
}

func (l *queryLog) logRequest(question *dns.Msg, answer *dns.Msg, result *dnsfilter.Result, elapsed time.Duration, addr net.Addr, upstream string) *logEntry {
	var q []byte
	var a []byte
	var err error
	ip := GetIPString(addr)

	if question != nil {
		q, err = question.Pack()
		if err != nil {
			log.Printf("failed to pack question for querylog: %s", err)
			return nil
		}
	}

	if answer != nil {
		a, err = answer.Pack()
		if err != nil {
			log.Printf("failed to pack answer for querylog: %s", err)
			return nil
		}
	}

	if result == nil {
		result = &dnsfilter.Result{}
	}

	now := time.Now()
	entry := logEntry{
		Question: q,
		Answer:   a,
		Result:   *result,
		Time:     now,
		Elapsed:  elapsed,
		IP:       ip,
		Upstream: upstream,
	}

	l.logBufferLock.Lock()
	l.logBuffer = append(l.logBuffer, &entry)
	needFlush := false
	if !l.flushPending {
		needFlush = len(l.logBuffer) >= logBufferCap
		if needFlush {
			l.flushPending = true
		}
	}
	l.logBufferLock.Unlock()

	// add it to running top
	err = l.runningTop.addEntry(&entry, question, now)
	if err != nil {
		log.Printf("Failed to add entry to running top: %s", err)
		// don't do failure, just log
	}

	// if buffer needs to be flushed to disk, do it now
	if needFlush {
		// write to file
		// do it in separate goroutine -- we are stalling DNS response this whole time
		go l.flushLogBuffer(false) // nolint
	}

	return &entry
}

func (l *queryLog) getQueryLogData(rightOffset, limit int) ([]*logEntry, int) {
	values := []*logEntry{}
	total := 0
	nDbEntries := 0
	nMemEntries := 0
	if rightOffset == -1 {
		rightOffset = 0
		limit = 0
	}

	l.logBufferLock.RLock()

	if limit == 0 {
		nMemEntries = len(l.logBuffer)
	} else {
		nMemEntries = len(l.logBuffer) - rightOffset
		if nMemEntries < 0 {
			nMemEntries = 0
		}
		if nMemEntries > limit {
			nMemEntries = limit
		}
	}

	r := l.OpenReader()
	if r != nil {
		if limit != 0 {
			limit -= nMemEntries
		}
		fileOff := 0
		if rightOffset > len(l.logBuffer) {
			fileOff = rightOffset - len(l.logBuffer)
		}

		r.BeginRead(fileOff, limit)
		for {
			ent := r.Next()
			if ent == nil {
				break
			}
			values = append(values, ent)
			nDbEntries++
		}
		total = r.Total()
		r.Close()
	}

	values = append(values, l.logBuffer[:nMemEntries]...)
	total += len(l.logBuffer)
	l.logBufferLock.RUnlock()

	log.Debug("querylog: returning %d items (%d from memory, %d from file) off:%d total:%d",
		len(values), nMemEntries, nDbEntries, rightOffset, total)
	return values, total
}

// getQueryLogJson returns a map with the current query log ready to be converted to a JSON
// rightOffset: Number of items to skip from the end:
//  ... (RESULT) [SKIP]
//  If -1, don't limit the result and return everything we have.
//
// * Read items from file
// * Read more recent items from memory (not yet written to file)
// * Process only N last items, where N is our limit:
//    OLD...NEW...
//        [......]
func (l *queryLog) getQueryLog(rightOffset int) map[string]interface{} {
	values, total := l.getQueryLogData(rightOffset, queryLogSize)

	var data = []map[string]interface{}{}
	n := len(values)
	for i := n - 1; i >= 0; i-- {
		entry := values[i]
		var q *dns.Msg
		var a *dns.Msg

		if len(entry.Question) > 0 {
			q = new(dns.Msg)
			if err := q.Unpack(entry.Question); err != nil {
				// ignore, log and move on
				log.Printf("Failed to unpack dns message question: %s", err)
				q = nil
			}
		}
		if len(entry.Answer) > 0 {
			a = new(dns.Msg)
			if err := a.Unpack(entry.Answer); err != nil {
				// ignore, log and move on
				log.Printf("Failed to unpack dns message question: %s", err)
				a = nil
			}
		}

		jsonEntry := map[string]interface{}{
			"reason":    entry.Result.Reason.String(),
			"elapsedMs": strconv.FormatFloat(entry.Elapsed.Seconds()*1000, 'f', -1, 64),
			"time":      entry.Time.Format(time.RFC3339),
			"client":    entry.IP,
		}
		if q != nil {
			jsonEntry["question"] = map[string]interface{}{
				"host":  strings.ToLower(strings.TrimSuffix(q.Question[0].Name, ".")),
				"type":  dns.Type(q.Question[0].Qtype).String(),
				"class": dns.Class(q.Question[0].Qclass).String(),
			}
		}

		if a != nil {
			jsonEntry["status"] = dns.RcodeToString[a.Rcode]
		}
		if len(entry.Result.Rule) > 0 {
			jsonEntry["rule"] = entry.Result.Rule
			jsonEntry["filterId"] = entry.Result.FilterID
		}

		if len(entry.Result.ServiceName) != 0 {
			jsonEntry["service_name"] = entry.Result.ServiceName
		}

		answers := answerToMap(a)
		if answers != nil {
			jsonEntry["answer"] = answers
		}

		data = append(data, jsonEntry)
	}

	obj := map[string]interface{}{}
	obj["total"] = total
	obj["data"] = data
	return obj
}

func answerToMap(a *dns.Msg) []map[string]interface{} {
	if a == nil || len(a.Answer) == 0 {
		return nil
	}

	var answers = []map[string]interface{}{}
	for _, k := range a.Answer {
		header := k.Header()
		answer := map[string]interface{}{
			"type": dns.TypeToString[header.Rrtype],
			"ttl":  header.Ttl,
		}
		// try most common record types
		switch v := k.(type) {
		case *dns.A:
			answer["value"] = v.A
		case *dns.AAAA:
			answer["value"] = v.AAAA
		case *dns.MX:
			answer["value"] = fmt.Sprintf("%v %v", v.Preference, v.Mx)
		case *dns.CNAME:
			answer["value"] = v.Target
		case *dns.NS:
			answer["value"] = v.Ns
		case *dns.SPF:
			answer["value"] = v.Txt
		case *dns.TXT:
			answer["value"] = v.Txt
		case *dns.PTR:
			answer["value"] = v.Ptr
		case *dns.SOA:
			answer["value"] = fmt.Sprintf("%v %v %v %v %v %v %v", v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
		case *dns.CAA:
			answer["value"] = fmt.Sprintf("%v %v \"%v\"", v.Flag, v.Tag, v.Value)
		case *dns.HINFO:
			answer["value"] = fmt.Sprintf("\"%v\" \"%v\"", v.Cpu, v.Os)
		case *dns.RRSIG:
			answer["value"] = fmt.Sprintf("%v %v %v %v %v %v %v %v %v", dns.TypeToString[v.TypeCovered], v.Algorithm, v.Labels, v.OrigTtl, v.Expiration, v.Inception, v.KeyTag, v.SignerName, v.Signature)
		default:
			// type unknown, marshall it as-is
			answer["value"] = v
		}
		answers = append(answers, answer)
	}

	return answers
}
