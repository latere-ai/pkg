// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// A stage's refusals travel from the egress proxy, in the stage's launcher,
// to StageSpec.OnRefused, in the process that launched the stage, through a
// pipe the driver opens: the launcher writes one line of JSON per refusal to
// its write end, which it inherits as refusalDescriptor and keeps from the
// stage it starts, and the driver reads the other end. Each line is the host
// and the port, and nothing else of the request.

// The limits on a stage's refusals.
const (
	// refusalWindow is how long a refusal of one host and port is reported
	// once, however often the stage retries it.
	refusalWindow = time.Minute
	// refusalBuffer is how many refusals wait to be sent before more are
	// dropped, so a reader that falls behind never holds up the proxy.
	refusalBuffer = 16
	// refusalsRemembered bounds the hosts and ports remembered within a
	// window, so a stage that asks for host after host grows nothing
	// without end; past it a refusal is dropped.
	refusalsRemembered = 256
	// refusalLineMax bounds one line on the pipe: a host name, a port and
	// the JSON around them fit well within it.
	refusalLineMax = 512
	// refusalFlush is how long a launcher whose stage has exited, and an
	// attached command's cleanup, wait for the refusals still on their way.
	refusalFlush = 2 * time.Second
)

// refusalDescriptor is the descriptor a launcher finds the refusals' pipe
// on, the first after stderr. A test replaces it.
var refusalDescriptor = 3

// refusal is one line on the pipe.
type refusal struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// reporter turns the proxy's refusals into lines on the pipe: each distinct
// host and port once a window, queued without ever blocking the proxy.
type reporter struct {
	mu    sync.Mutex
	now   func() time.Time
	seen  map[string]time.Time
	queue chan refusal
}

func newReporter() *reporter {
	return &reporter{now: time.Now, seen: map[string]time.Time{}, queue: make(chan refusal, refusalBuffer)}
}

// report queues the refusal of host on port, unless the same was reported
// within the window, the host is not a well-formed name or address, the
// port is not a number from 1 to 65535, or the queue is full.
func (r *reporter) report(host, port string) {
	host = normalizeHost(host)
	canonical, ok := portNumber(port)
	if !ok || !reportable(host) {
		return
	}
	key := net.JoinHostPort(host, canonical)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if at, ok := r.seen[key]; ok && now.Sub(at) < refusalWindow {
		return
	}
	if len(r.seen) >= refusalsRemembered {
		for remembered, at := range r.seen {
			if now.Sub(at) >= refusalWindow {
				delete(r.seen, remembered)
			}
		}
		if len(r.seen) >= refusalsRemembered {
			return
		}
	}
	number, _ := strconv.Atoi(canonical)
	select {
	case r.queue <- refusal{Host: host, Port: number}:
		r.seen[key] = now
	default:
	}
}

// send writes each queued refusal to w as a line of JSON until done is
// closed, then those still queued, and returns. A write that fails, a
// reader gone, ends it: the refusals after it are dropped, and the stage's
// network carries on.
func (r *reporter) send(w io.Writer, done <-chan struct{}) {
	write := func(item refusal) bool {
		line, err := json.Marshal(item)
		if err != nil {
			return false
		}
		_, err = w.Write(append(line, '\n'))
		return err == nil
	}
	for {
		select {
		case item := <-r.queue:
			if !write(item) {
				return
			}
		case <-done:
			for {
				select {
				case item := <-r.queue:
					if !write(item) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// openRefusals is the launcher's end of the pipe: refusalDescriptor, marked
// to close when the launcher starts the stage, so the stage never holds it
// and cannot write a refusal of its own. It is taken only when it is a
// pipe. A test replaces it.
var openRefusals = func() (io.WriteCloser, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(refusalDescriptor, &stat); err != nil {
		return nil, fmt.Errorf("the refusals' pipe: %w", err)
	}
	syscall.CloseOnExec(refusalDescriptor)
	if stat.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return nil, errors.New("the refusals' descriptor is not a pipe")
	}
	return os.NewFile(uintptr(refusalDescriptor), "refusals"), nil
}

// decodeRefusal reads one line of the pipe: a well-formed host in its
// normalized form and a port from 1 to 65535.
func decodeRefusal(line []byte) (string, int, bool) {
	var item refusal
	if err := json.Unmarshal(line, &item); err != nil {
		return "", 0, false
	}
	if item.Port < 1 || item.Port > 65535 || normalizeHost(item.Host) != item.Host || !reportable(item.Host) {
		return "", 0, false
	}
	return item.Host, item.Port, true
}

// deliverRefusals calls onRefused with each refusal read from r until r
// ends. A line that is not a refusal is skipped; one longer than any
// refusal ends the delivery, and the rest of r is read and dropped, so the
// launcher's writes never wait on it.
func deliverRefusals(r io.Reader, onRefused func(host string, port int)) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, refusalLineMax), refusalLineMax)
	for scanner.Scan() {
		if host, port, ok := decodeRefusal(scanner.Bytes()); ok {
			onRefused(host, port)
		}
	}
	if scanner.Err() != nil {
		_, _ = io.Copy(io.Discard, r)
	}
}

// refusalPipe is the driver's side of one stage's refusals: the end it
// reads and delivers, and the end the launcher inherits.
type refusalPipe struct {
	read, write *os.File
	// delivered is closed when the delivery has ended; nil until it starts.
	delivered chan struct{}
	once      sync.Once
	// mu guards stopped, which keeps any call of the consumer's OnRefused
	// from beginning once close has given up waiting. A call begins when it
	// is decided under mu, which is held for the decision and never during
	// the call.
	mu      sync.Mutex
	stopped bool
}

// newRefusalPipe opens the pipe for a stage whose OnRefused is set. A test
// replaces it.
var newRefusalPipe = func() (*refusalPipe, error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("open the pipe for the stage's refusals: %w", err)
	}
	return &refusalPipe{read: read, write: write}, nil
}

// files are the files the launcher inherits after stderr: the pipe's write
// end, or none.
func (p *refusalPipe) files() []*os.File {
	if p == nil {
		return nil
	}
	return []*os.File{p.write}
}

// deliver starts delivering the refusals read from the pipe to onRefused,
// one call at a time, and closes the read end when the pipe ends.
func (p *refusalPipe) deliver(onRefused func(host string, port int)) {
	if p == nil {
		return
	}
	delivered := make(chan struct{})
	p.delivered = delivered
	go func() {
		defer close(delivered)
		defer func() { _ = p.read.Close() }()
		deliverRefusals(p.read, func(host string, port int) {
			p.mu.Lock()
			stopped := p.stopped
			p.mu.Unlock()
			if !stopped {
				onRefused(host, port)
			}
		})
	}()
}

// started closes this process's copy of the write end once the launcher
// holds its own, so the delivery ends when the launcher does.
func (p *refusalPipe) started() {
	if p == nil {
		return
	}
	_ = p.write.Close()
}

// close closes the write end, waits up to wait for a delivery that started
// to deliver what is on the pipe, and then stops it: no call begins after
// close returns, while one that began before is not waited for past wait.
// It may be called from within OnRefused. It is idempotent.
func (p *refusalPipe) close(wait time.Duration) {
	if p == nil {
		return
	}
	p.once.Do(func() {
		_ = p.write.Close()
		if p.delivered != nil {
			timer := time.NewTimer(wait)
			select {
			case <-p.delivered:
			case <-timer.C:
			}
			timer.Stop()
		}
		p.mu.Lock()
		p.stopped = true
		p.mu.Unlock()
		_ = p.read.Close()
	})
}
