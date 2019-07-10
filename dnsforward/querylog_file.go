package dnsforward

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"math"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	bolt "github.com/etcd-io/bbolt"
)

var (
	fileWriteLock sync.Mutex
)

const enableGzip = false

// flushLogBuffer flushes the current buffer to file and resets the current buffer
func (l *queryLog) flushLogBuffer(fullFlush bool) error {
	l.fileFlushLock.Lock()
	defer l.fileFlushLock.Unlock()

	// flush remainder to file
	l.logBufferLock.Lock()
	needFlush := len(l.logBuffer) >= logBufferCap
	if !needFlush && !fullFlush {
		l.logBufferLock.Unlock()
		return nil
	}
	flushBuffer := l.logBuffer
	l.logBuffer = nil
	l.flushPending = false
	l.logBufferLock.Unlock()
	err := l.flushToFile(flushBuffer)
	if err != nil {
		log.Error("Saving querylog to file failed: %s", err)
		return err
	}
	return nil
}

// itob returns an 8-byte big endian representation of v.
func itob(v int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

// flushToFile saves the specified log entries to the query log file
func (l *queryLog) flushToFile(buffer []*logEntry) error {
	if len(buffer) == 0 {
		log.Debug("querylog: there's nothing to write to a file")
		return nil
	}
	if l.db == nil {
		return nil
	}
	start := time.Now()

	tx, err := l.db.Begin(true)
	if err != nil {
		log.Error("db.Begin: %s", err)
		return nil
	}
	defer tx.Rollback()

	bkt, err := tx.CreateBucketIfNotExists([]byte("querylog"))
	if err != nil {
		log.Error("tx.CreateBucketIfNotExists: %s", err)
		return nil
	}

	total := 0
	for _, entry := range buffer {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)

		err := enc.Encode(entry)
		if err != nil {
			log.Error("Failed to marshal entry: %s", err)
			return err
		}

		id, _ := bkt.NextSequence()
		err = bkt.Put(itob(int(id)), buf.Bytes())
		if err != nil {
			log.Error("bkt.Put: %s", err)
			return nil
		}
		// log.Tracef("Put: %d = %v", id, buf.Bytes())

		total += buf.Len()
	}

	err = tx.Commit()
	if err != nil {
		log.Error("tx.Commit: %s", err)
		return nil
	}

	elapsed := time.Since(start)
	log.Debug("querylog: %d elements serialized in %v: %d kB, %v/entry, %v/entry", len(buffer), elapsed, total/1024, float64(total)/float64(len(buffer)), elapsed/time.Duration(len(buffer)))
	return nil
}

// Remove old items from query log
func (l *queryLog) rotateQueryLog() error {
	now := time.Now()
	validFrom := now.Unix() - int64(l.timeLimit*60*60)

	log.Debug("querylog: removing old items")

	tx, err := l.db.Begin(true)
	if err != nil {
		log.Error("db.Begin: %s", err)
		return nil
	}
	defer tx.Rollback()

	bkt := tx.Bucket([]byte("querylog"))
	if bkt == nil {
		return nil
	}

	cur := bkt.Cursor()

	n := 0
	for k, v := cur.First(); k != nil; k, v = cur.Next() {

		var entry logEntry
		var buf bytes.Buffer
		buf.Write(v)
		dec := gob.NewDecoder(&buf)
		err := dec.Decode(&entry)
		if err != nil {
			log.Error("Failed to decode: %s", err)
			continue
		}

		if entry.Time.Unix() >= validFrom {
			break
		}

		// log.Tracef("Removed: %v", k)

		cur.Delete()
		n++
	}

	err = tx.Commit()
	if err != nil {
		log.Error("tx.Commit: %s", err)
		return nil
	}

	log.Debug("querylog: removed %d old items", n)
	return nil
}

func (l *queryLog) periodicQueryLogRotate() {
	for {
		err := l.rotateQueryLog()
		if err != nil {
			log.Error("Failed to rotate querylog: %s", err)
			// do nothing, continue rotating
		}
		time.Sleep(queryLogRotationPeriod)
	}
}

// Reader is the DB reader context
type Reader struct {
	tx  *bolt.Tx
	bkt *bolt.Bucket
	cur *bolt.Cursor

	now time.Time

	key []byte
	val []byte

	start uint // ID of the first element to return
	count uint // returned elements counter
	limit uint // maximum number of elements
}

// OpenReader locks the file and returns reader object or nil on error
func (l *queryLog) OpenReader() *Reader {
	r := Reader{}
	r.now = time.Now()

	var err error
	r.tx, err = l.db.Begin(false)
	if err != nil {
		log.Error("db.Begin: %s", err)
		return nil
	}
	return &r
}

// BeginRead starts reading
// off: Number of items to skip from the end
// num: Read the last N elements;  0: read all items
func (r *Reader) BeginRead(off, num int) {
	r.bkt = r.tx.Bucket([]byte("querylog"))
	if r.bkt == nil {
		return
	}
	r.cur = r.bkt.Cursor()

	// ...[.......].......
	//     ^       ^     ^
	//     START   END   SEQ

	if num == 0 {
		r.key, r.val = r.cur.First()
		if off != 0 {
			log.Debug("querylog: not supported")
			return
		}
		r.limit = math.MaxUint64

	} else {

		start := int(r.bkt.Sequence()+1) - (num + off)
		if start <= 0 {
			start = 1
		}

		r.limit = uint(num)
		r.key, r.val = r.cur.Seek(itob(start))
		if r.key != nil {
			id := uint(binary.BigEndian.Uint64(r.key))
			r.limit = uint(r.bkt.Sequence()+1) - uint(off) - uint(id)
		}
		r.start = uint(start)
	}
}

// Close closes the reader
func (r *Reader) Close() {
	r.tx.Rollback()

	elapsed := time.Since(r.now)
	var perunit time.Duration
	if r.count > 0 {
		perunit = elapsed / time.Duration(r.count)
	}
	seq := 0
	if r.bkt != nil {
		r.bkt.Sequence()
	}
	log.Debug("querylog: read %d entries @%d seq=%d in %v, %v/entry",
		r.count, r.start, seq, elapsed, perunit)
}

// Next returns the next entry or nil if reading is finished
func (r *Reader) Next() *logEntry {
	for {
		if r.key == nil || r.count == r.limit {
			return nil
		}

		log.Tracef("Read: %v size:%d", r.key, len(r.val))

		var entry logEntry
		var buf bytes.Buffer
		buf.Write(r.val)
		dec := gob.NewDecoder(&buf)
		err := dec.Decode(&entry)
		if err != nil {
			log.Debug("dec.Decode: %s", err)
			r.key, r.val = r.cur.Next()
			continue
		}

		r.key, r.val = r.cur.Next()
		r.count++
		return &entry
	}
}

// Total returns the total number of items
func (r *Reader) Total() int {
	if r.bkt == nil {
		return 0
	}

	cur := r.bkt.Cursor()
	k, _ := cur.First()
	if k == nil {
		return 0
	}
	first := int(binary.BigEndian.Uint64(k))
	return int(r.bkt.Sequence()+1) - first
}
