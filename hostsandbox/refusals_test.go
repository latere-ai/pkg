// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// event is one refusal as a test receives it.
type event struct {
	host string
	port int
}

// events collects the refusals a reporter sends, decoded as an embedder
// decodes them.
type events struct {
	mu   sync.Mutex
	got  []event
	sent chan struct{}
}

func newEvents() *events { return &events{sent: make(chan struct{}, 1024)} }

func (e *events) add(host string, port int) {
	e.mu.Lock()
	e.got = append(e.got, event{host, port})
	e.mu.Unlock()
	e.sent <- struct{}{}
}

func (e *events) list() []event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]event(nil), e.got...)
}

// wait waits for n more refusals, or fails the test at its deadline.
func (e *events) wait(t *testing.T, n int) {
	t.Helper()
	timer := time.NewTimer(time.Until(until(t)))
	defer timer.Stop()
	for range n {
		select {
		case <-e.sent:
		case <-timer.C:
			t.Fatalf("waited for %d refusals; have %v", n, e.list())
		}
	}
}

// reportingProxy starts the egress proxy for network with every destination
// dialed to target, its refusals sent through a pipe and delivered as an
// embedder's are. It returns the proxy's address, the proxy, and what was
// delivered.
func reportingProxy(t *testing.T, network Network, target string) (string, *egress, *events) {
	t.Helper()
	e, err := egressFor(network, io.Discard, true)
	if err != nil {
		t.Fatal(err)
	}
	e.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
	e.reporter = newReporter()
	read, write := io.Pipe()
	done := make(chan struct{})
	sent := make(chan struct{})
	go func() {
		e.reporter.send(write, done)
		_ = write.Close()
		close(sent)
	}()
	got := newEvents()
	delivered := make(chan struct{})
	go func() {
		deliverRefusals(read, got.add)
		close(delivered)
	}()
	t.Cleanup(func() {
		close(done)
		<-sent
		<-delivered
	})
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	return server.Listener.Addr().String(), e, got
}

// TestARefusalCarriesItsHostAndPortAlone checks what an embedder is told of a
// refusal: the host, as the stage asked for it in its comparable form, and
// the port, for a CONNECT and for a plain request, and nothing of the
// request line, its headers, path, query or body.
func TestARefusalCarriesItsHostAndPortAlone(t *testing.T) {
	upstream := echoServer(t)
	address, _, got := reportingProxy(t, Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}, upstream)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := fmt.Fprintf(conn, "CONNECT Other.TEST.:0443 HTTP/1.1\r\nHost: Other.TEST.:0443\r\nProxy-Authorization: Basic c2VjcmV0\r\nUser-Agent: secret-agent\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if status, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.Contains(status, " 403 ") {
		t.Fatalf("CONNECT = %q, %v", status, err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://other.test/secret/path?token=secret", strings.NewReader("secret body"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("Cookie", "session=secret")
	response, err := throughProxy(t, "http://"+address).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("a plain request for another host = %d", response.StatusCode)
	}
	got.wait(t, 2)
	want := []event{{"other.test", 443}, {"other.test", 80}}
	if list := got.list(); fmt.Sprint(list) != fmt.Sprint(want) {
		t.Fatalf("the refusals = %v, want %v", list, want)
	}
}

// TestARefusalIsEncodedAsItsHostAndPortAlone checks the line the launcher
// writes for a refusal, which is all that crosses to the embedder.
func TestARefusalIsEncodedAsItsHostAndPortAlone(t *testing.T) {
	r := newReporter()
	r.report("Other.TEST.", "0443")
	r.report("2001:DB8::1", "80")
	done := make(chan struct{})
	close(done)
	var out bytes.Buffer
	r.send(&out, done)
	if want := "{\"host\":\"other.test\",\"port\":443}\n{\"host\":\"2001:db8::1\",\"port\":80}\n"; out.String() != want {
		t.Fatalf("the lines = %q, want %q", out.String(), want)
	}
}

// TestRefusalsAreReportedOnceAWindow checks that a refusal repeated by a
// stage that retries is reported once until the window passes, and that a
// refusal of the same host on another port, or of another host, is its own.
func TestRefusalsAreReportedOnceAWindow(t *testing.T) {
	now := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	r := newReporter()
	r.now = func() time.Time { return now }
	for range 5 {
		r.report("retry.test", "443")
		r.report("RETRY.test.", "443")
	}
	r.report("retry.test", "80")
	r.report("other.test", "443")
	now = now.Add(refusalWindow - time.Second)
	r.report("retry.test", "443")
	now = now.Add(time.Second)
	r.report("retry.test", "443")
	var got []string
	for len(r.queue) > 0 {
		refusal := <-r.queue
		got = append(got, net.JoinHostPort(refusal.Host, strconv.Itoa(refusal.Port)))
	}
	if want := "[retry.test:443 retry.test:80 other.test:443 retry.test:443]"; fmt.Sprint(got) != want {
		t.Fatalf("the refusals = %v, want %s", got, want)
	}
}

// TestRefusalsRememberABoundedNumberOfHosts checks that the hosts a reporter
// remembers are bounded: past the bound, a refusal is dropped until a
// remembered one's window passes, so a stage that asks for host after host
// grows nothing without end.
func TestRefusalsRememberABoundedNumberOfHosts(t *testing.T) {
	now := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	r := newReporter()
	r.now = func() time.Time { return now }
	reported := 0
	for i := range refusalsRemembered + 10 {
		r.report("host-"+strconv.Itoa(i)+".test", "443")
		for len(r.queue) > 0 {
			<-r.queue
			reported++
		}
	}
	if reported != refusalsRemembered || len(r.seen) != refusalsRemembered {
		t.Fatalf("reported %d and remembered %d, want %d of each", reported, len(r.seen), refusalsRemembered)
	}
	now = now.Add(refusalWindow)
	r.report("late.test", "443")
	if len(r.queue) != 1 || len(r.seen) != 1 {
		t.Fatalf("after the window, queued %d and remembered %d, want 1 of each", len(r.queue), len(r.seen))
	}
}

// TestRefusalsNeverHoldUpTheProxy checks that an embedder that does not read
// its refusals never holds up the proxy: every refusal is still answered at
// once, and those past a small buffer are dropped.
func TestRefusalsNeverHoldUpTheProxy(t *testing.T) {
	e := denylist(t, Network{Blocked: []string{"*.blocked.test"}})
	e.reporter = newReporter()
	read, write := io.Pipe()
	done := make(chan struct{})
	sent := make(chan struct{})
	go func() {
		e.reporter.send(write, done)
		close(sent)
	}()
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	started := time.Now()
	for i := range 4 * refusalBuffer {
		if _, _, status := connect(t, server.Listener.Addr().String(), "h"+strconv.Itoa(i)+".blocked.test:443"); !strings.Contains(status, " 403 ") {
			t.Fatalf("refusal %d = %q", i, status)
		}
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("the refusals took %v with nobody reading them", elapsed)
	}
	close(done)
	got := newEvents()
	delivered := make(chan struct{})
	go func() {
		deliverRefusals(read, got.add)
		close(delivered)
	}()
	<-sent
	_ = write.Close()
	<-delivered
	// The buffer, and the one the sender held when it found nobody reading.
	if n := len(got.list()); n < refusalBuffer || n > refusalBuffer+1 {
		t.Fatalf("delivered %d refusals, want the %d buffered", n, refusalBuffer)
	}
}

// TestASenderStopsWhenNobodyReads checks that a sender whose reader has gone
// ends, rather than the launcher it runs in.
func TestASenderStopsWhenNobodyReads(t *testing.T) {
	r := newReporter()
	read, write := io.Pipe()
	_ = read.Close()
	ended := make(chan struct{})
	go func() {
		r.send(write, make(chan struct{}))
		close(ended)
	}()
	r.report("gone.test", "443")
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the sender went on after its reader had gone")
	}
}

// TestOnlyANameOrAnAddressIsReported checks that a refusal is reported only
// for a host that is a well-formed name or address, on a port that is a
// number: the host is what the stage asked for, and it reaches a prompt, so
// a wildcard, a character outside ASCII or a control character never does.
func TestOnlyANameOrAnAddressIsReported(t *testing.T) {
	r := newReporter()
	for _, c := range [][2]string{
		{"*.wild.test", "443"}, {"*", "443"}, {"évil.test", "443"}, {"evil.test\u202e", "443"}, {"evil\x1b[2J.test", "443"},
		{"", "443"}, {"evil..test", "443"}, {"fe80::1%en0", "443"}, {"evil.test", "abc"}, {"evil.test", "0"},
		{"evil.test", "99999"}, {strings.Repeat("a.", 127) + "test", "443"},
		// A number a resolver reads as an address, and an address not in
		// its canonical form, which an Allow of it would not admit.
		{"2130706433", "443"}, {"0x7f.0.0.1", "443"}, {"::ffff:1.2.3.4", "443"}, {"2001:db8:0::1", "443"}, {"2001:0db8::1", "443"},
		{"64:ff9b::101:101", "443"}, {"64:ff9b::1.1.1.1", "443"},
	} {
		r.report(c[0], c[1])
	}
	if len(r.queue) != 0 {
		t.Fatalf("reported %d refusals of hosts that are not names", len(r.queue))
	}
	r.report("xn--vil-bma.test", "443")
	r.report("203.0.114.7", "80")
	r.report("2001:DB8::1", "443")
	if len(r.queue) != 3 {
		t.Fatalf("queued %d refusals of names, want 3", len(r.queue))
	}
}

// TestARefusalNoAllowCanLiftIsNotReported checks that a refusal is not
// reported when the network would refuse the host by address whatever its
// names admit: a localhost name, or an address the network's check refuses,
// which for an allowlist is this machine and its link and for a deny list
// every address that is not public.
func TestARefusalNoAllowCanLiftIsNotReported(t *testing.T) {
	noNetworks(t)
	for _, c := range []struct {
		network  Network
		reported []string
		refused  []string
	}{
		{
			Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}},
			[]string{"other.test:443", "10.0.0.1:443", "8.8.8.8:22"},
			[]string{"localhost:443", "app.localhost:443", "127.0.0.1:443", "169.254.169.254:80", "[::1]:443", "[fe80::1]:443"},
		},
		{
			Network{Mode: NetworkDenylist, Blocked: []string{"evil.test", "1.1.1.1"}},
			[]string{"evil.test:443", "1.1.1.1:443", "8.8.8.8:22", "example.com:22"},
			[]string{"localhost:5432", "10.0.0.1:22", "192.168.1.1:8443", "127.0.0.1:22", "[fd00::1]:22", "100.64.0.1:22", "198.18.0.1:22"},
		},
	} {
		address, _, got := reportingProxy(t, c.network, echoServer(t))
		for _, target := range append(append([]string{}, c.refused...), c.reported...) {
			if status, _ := answer(t, address, target); !strings.Contains(status, " 403 ") {
				t.Fatalf("%s: CONNECT %s = %q, want it refused", c.network.Mode, target, status)
			}
		}
		got.wait(t, len(c.reported))
		var want []event
		for _, target := range c.reported {
			host, port, _ := net.SplitHostPort(target)
			number, _ := strconv.Atoi(port)
			want = append(want, event{host, number})
		}
		if fmt.Sprint(got.list()) != fmt.Sprint(want) {
			t.Errorf("%s: reported %v, want %v", c.network.Mode, got.list(), want)
		}
	}
}

// TestNoRefusalIsDeliveredAfterTheCleanup checks that once an attached
// command's cleanup has waited its time, it stops the delivery and returns,
// however long a call in progress takes, and that no call starts after it
// returns.
func TestNoRefusalIsDeliveredAfterTheCleanup(t *testing.T) {
	pipe, err := newRefusalPipe()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := fmt.Fprintf(pipe.write, "{\"host\":\"h%d.test\",\"port\":443}\n", i); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	calls, inCall := 0, false
	pipe.deliver(func(string, int) {
		mu.Lock()
		calls++
		inCall = true
		mu.Unlock()
		time.Sleep(time.Second)
		mu.Lock()
		inCall = false
		mu.Unlock()
	})
	started := time.Now()
	pipe.close(100 * time.Millisecond)
	if elapsed := time.Since(started); elapsed > 600*time.Millisecond {
		t.Fatalf("the cleanup waited %v for a call in progress", elapsed)
	}
	mu.Lock()
	after, busy := calls, inCall
	mu.Unlock()
	if after != 1 || !busy {
		t.Fatalf("when the cleanup returned, %d of 3 calls had started, and one was in progress: %v", after, busy)
	}
	select {
	case <-pipe.delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("the delivery did not end after the cleanup")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != after {
		t.Fatalf("%d calls started after the cleanup returned", calls-after)
	}
}

// TestTheCleanupNeverWaitsOnTheConsumer checks that the cleanup returns in
// its time when OnRefused waits on the goroutine calling the cleanup, as an
// event loop's callback does, and when OnRefused calls the cleanup itself.
func TestTheCleanupNeverWaitsOnTheConsumer(t *testing.T) {
	pipe, err := newRefusalPipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(pipe.write, `{"host":"loop.test","port":443}`); err != nil {
		t.Fatal(err)
	}
	loop := make(chan event)
	called := make(chan struct{})
	pipe.deliver(func(host string, port int) {
		close(called)
		loop <- event{host, port}
	})
	<-called
	returned := make(chan struct{})
	go func() {
		pipe.close(100 * time.Millisecond)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the cleanup waited on a call that waits on its caller")
	}
	if got := <-loop; got != (event{"loop.test", 443}) {
		t.Fatalf("the loop got %v", got)
	}

	reentrant, err := newRefusalPipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(reentrant.write, `{"host":"again.test","port":443}`); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	reentrant.deliver(func(string, int) {
		reentrant.close(100 * time.Millisecond)
		close(done)
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a cleanup called from OnRefused did not return")
	}
}

// TestADeliveryThatEndsClosesItsPipe checks that a launched stage's pipe is
// closed once its launcher has exited and every refusal is delivered, with
// nothing left for the garbage collector.
func TestADeliveryThatEndsClosesItsPipe(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), os.Args[0])
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}
	spec.Env = map[string]string{connectVariable: "refused.test:443", "GOCOVERDIR": t.TempDir()}
	got := newEvents()
	spec.OnRefused = got.add
	saved := newRefusalPipe
	t.Cleanup(func() { newRefusalPipe = saved })
	var opened *refusalPipe
	newRefusalPipe = func() (*refusalPipe, error) {
		pipe, err := saved()
		opened = pipe
		return pipe, err
	}
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, driver, handle)
	got.wait(t, 1)
	select {
	case <-opened.delivered:
	case <-time.After(time.Until(until(t))):
		t.Fatal("the delivery did not end after the stage")
	}
	if _, err := opened.read.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("the pipe's read end is open after its delivery ended: %v", err)
	}
}

// TestARefusalAtDialTimeIsNotReported checks that a destination refused for
// the address its name resolves to is not reported: no change to the
// stage's names admits it, so there is nothing for the person to allow.
func TestARefusalAtDialTimeIsNotReported(t *testing.T) {
	noNetworks(t)
	e, err := egressFor(Network{Mode: NetworkDenylist}, io.Discard, false)
	if err != nil {
		t.Fatal(err)
	}
	e.reporter = newReporter()
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	if _, _, status := connect(t, server.Listener.Addr().String(), "localhost:443"); !strings.Contains(status, " 502 ") {
		t.Fatalf("CONNECT localhost = %q", status)
	}
	if len(e.reporter.queue) != 0 {
		t.Fatal("a refusal by address was reported")
	}
}

// TestDeliveryReadsOnlyWellFormedRefusals checks what an embedder's delivery
// accepts from the pipe: a line of a host and a port in range, and nothing
// else, a line longer than any refusal ending it.
func TestDeliveryReadsOnlyWellFormedRefusals(t *testing.T) {
	got := newEvents()
	input := strings.Join([]string{
		`{"host":"ok.test","port":443}`, `{"host":"OK.test","port":443}`, `{"host":"ok.test","port":0}`,
		`{"host":"2130706433","port":443}`, `{"host":"::ffff:1.2.3.4","port":443}`,
		`{"host":"ok.test","port":70000}`, `{"host":"*.ok.test","port":443}`, `{"host":"ok.test"}`, `not json`,
		`{"host":"ok.test","port":"443"}`, `{"host":"also.test","port":80,"path":"/x"}`, `{"host":"","port":443}`,
		strings.Repeat("x", refusalLineMax+1), `{"host":"after.test","port":443}`,
	}, "\n")
	deliverRefusals(strings.NewReader(input), got.add)
	if want := "[{ok.test 443} {also.test 80}]"; fmt.Sprint(got.list()) != want {
		t.Fatalf("delivered %v, want %s", got.list(), want)
	}
}

// FuzzDecodeRefusal checks that whatever line reaches an embedder, a
// refusal it decodes names a well-formed host in its comparable form and a
// port in range.
func FuzzDecodeRefusal(f *testing.F) {
	for _, seed := range []string{`{"host":"ok.test","port":443}`, `{"host":"*.x","port":1}`, `{"host":"é","port":80}`, `{}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		host, port, ok := decodeRefusal(line)
		if !ok {
			return
		}
		if !reportable(host) || normalizeHost(host) != host || port < 1 || port > 65535 {
			t.Fatalf("decoded %q, %d from %q", host, port, line)
		}
	})
}

// FuzzReportedHost checks that whatever host and port a stage asks for, a
// refusal reported for it names a well-formed host and a port in range.
func FuzzReportedHost(f *testing.F) {
	for _, seed := range []string{"ok.test", "*.x.test", "évil.test", "evil.test\u202e", "1.2.3.4", "::1"} {
		f.Add(seed, "443")
	}
	f.Fuzz(func(t *testing.T, host, port string) {
		r := newReporter()
		r.report(host, port)
		if len(r.queue) == 0 {
			return
		}
		refusal := <-r.queue
		if !reportable(refusal.Host) || normalizeHost(refusal.Host) != refusal.Host || refusal.Port < 1 || refusal.Port > 65535 {
			t.Fatalf("reported %q, %d for %q, %q", refusal.Host, refusal.Port, host, port)
		}
	})
}

// connectVariable names a target that makes this test binary, running as a
// stage, send a CONNECT for it through the proxy its HTTPS_PROXY names and
// print the answer's status line.
const connectVariable = "HOSTSANDBOX_TEST_CONNECT"

// forgeVariable makes this test binary, running as a stage, write a forged
// refusal into every descriptor above stderr it holds, and print how many
// took it.
const forgeVariable = "HOSTSANDBOX_TEST_FORGE"

// connectStage sends one CONNECT for each target, separated by commas,
// through the stage's proxy.
func connectStage(targets string) int {
	proxy := strings.TrimPrefix(os.Getenv("HTTPS_PROXY"), "http://")
	for target := range strings.SplitSeq(targets, ",") {
		conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
			fmt.Println(err)
			return 1
		}
		status, err := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if err != nil {
			fmt.Println(err)
			return 1
		}
		fmt.Println(strings.TrimSpace(status))
	}
	return 0
}

// forgeStage writes a forged refusal into every descriptor from 3 to 255
// that it holds, as a stage would to have its own host offered to the
// person, and prints how many accepted the write.
func forgeStage() int {
	written := 0
	for fd := 3; fd < 256; fd++ {
		if _, err := syscall.Write(fd, []byte(`{"host":"forged.test","port":443}`+"\n")); err == nil {
			written++
		}
	}
	fmt.Printf("forged into %d\n", written)
	return 0
}

// TestTheLauncherSendsItsStagesRefusals runs the launcher in this process
// with a stage, this test binary, that asks its proxy for a host the
// allowlist does not name and then exits at once, and checks that the
// refusal is sent before the launcher returns.
func TestTheLauncherSendsItsStagesRefusals(t *testing.T) {
	fakeSandboxExec(t)
	var sent bytes.Buffer
	saved := openRefusals
	openRefusals = func() (io.WriteCloser, error) { return nopCloser{&sent}, nil }
	t.Cleanup(func() { openRefusals = saved })
	t.Setenv(connectVariable, "refused.test:443,allowed.test:22,refused.test:443")
	t.Setenv("GOCOVERDIR", t.TempDir())
	path, _ := writeStage(t, stageFile{
		Profile:     Profile{Network: Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}},
		Argv:        []string{os.Args[0]},
		SandboxExec: sandboxExec,
		Refusals:    true,
	})
	// The stage's stderr is copied into the buffer the proxy writes its
	// lines to, so it is one a lock guards.
	var stdout bytes.Buffer
	stderr := &lockedBuffer{}
	if code := runLauncher(path, strings.NewReader(""), &stdout, stderr); code != 0 {
		t.Fatalf("the launcher exited %d: %s %s", code, stdout.String(), stderr.String())
	}
	if want := "{\"host\":\"refused.test\",\"port\":443}\n{\"host\":\"allowed.test\",\"port\":22}\n"; sent.String() != want {
		t.Fatalf("the launcher sent %q, want %q; the stage said %q", sent.String(), want, stdout.String())
	}
	if !strings.Contains(stderr.String(), "refused a connection to refused.test:443") {
		t.Fatalf("the refusal's line for the stage is gone: %q; stdout %q", stderr.String(), stdout.String())
	}
	// A stage file that asks for no refusals opens no pipe.
	openRefusals = func() (io.WriteCloser, error) {
		t.Fatal("opened the refusals of a stage that wants none")
		return nil, nil
	}
	path, _ = writeStage(t, stageFile{Profile: Profile{Network: Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}}, Argv: []string{os.Args[0]}, SandboxExec: sandboxExec})
	if code := runLauncher(path, strings.NewReader(""), io.Discard, io.Discard); code != 0 {
		t.Fatalf("the launcher exited %d", code)
	}
	// A pipe that cannot be opened costs the refusals, not the stage.
	openRefusals = func() (io.WriteCloser, error) { return nil, errors.New("no pipe") }
	path, _ = writeStage(t, stageFile{Profile: Profile{Network: Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}}, Argv: []string{os.Args[0]}, SandboxExec: sandboxExec, Refusals: true})
	stderr = &lockedBuffer{}
	if code := runLauncher(path, strings.NewReader(""), io.Discard, stderr); code != 0 || !strings.Contains(stderr.String(), "no pipe") {
		t.Fatalf("the launcher exited %d without its refusals: %q", code, stderr.String())
	}
}

type nopCloser struct{ io.Writer }

// fcntl reads a descriptor's flags with cmd.
func fcntl(fd, cmd int) (int, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(flags), nil
}

func (nopCloser) Close() error { return nil }

// TestOpenRefusalsTakesOnlyAPipe checks the launcher's side of the pipe: it
// takes descriptor 3 only when it is a pipe, and keeps it from the stage it
// starts.
func TestOpenRefusalsTakesOnlyAPipe(t *testing.T) {
	saved := refusalDescriptor
	t.Cleanup(func() { refusalDescriptor = saved })
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
	// A descriptor of its own, which the file openRefusals returns closes.
	fd, err := syscall.Dup(int(write.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	refusalDescriptor = fd
	file, err := openRefusals()
	if err != nil {
		t.Fatalf("a pipe was not taken: %v", err)
	}
	flags, err := fcntl(refusalDescriptor, syscall.F_GETFD)
	if err != nil || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("the pipe stays open across exec: flags %d, %v", flags, err)
	}
	_ = file.Close()
	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = regular.Close() })
	refusalDescriptor = int(regular.Fd())
	if _, err := openRefusals(); err == nil {
		t.Fatal("a regular file was taken for the refusals")
	}
	refusalDescriptor = 1023
	if _, err := openRefusals(); err == nil {
		t.Fatal("a descriptor that is not open was taken for the refusals")
	}
}

// TestADriverDeliversAStagesRefusals runs a stage with an allowlist, this
// test binary asking its proxy for hosts, attached and detached, and checks
// that OnRefused is called with each distinct refusal, that an attached
// command's are all delivered by the time its cleanup returns, and that a
// forged refusal the stage writes into every descriptor it holds reaches
// nobody.
func TestADriverDeliversAStagesRefusals(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), os.Args[0])
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}
	spec.Env = map[string]string{connectVariable: "refused.test:443,refused.test:443,refused.test:80", forgeVariable: "1", "GOCOVERDIR": t.TempDir()}
	got := newEvents()
	spec.OnRefused = got.add

	command, cleanup, err := driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the stage: %v\n%s", err, output)
	}
	cleanup()
	cleanup()
	if want := "[{refused.test 443} {refused.test 80}]"; fmt.Sprint(got.list()) != want {
		t.Fatalf("after the cleanup, delivered %v, want %s; the stage said %q", got.list(), want, output)
	}
	if !strings.Contains(string(output), "forged into 0") {
		t.Fatalf("the stage held a descriptor it could write: %q", output)
	}

	launched := newEvents()
	spec.OnRefused = launched.add
	handle, err := driver.Launch(context.Background(), spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	waitFor(t, driver, handle)
	launched.wait(t, 2)
	if want := "[{refused.test 443} {refused.test 80}]"; fmt.Sprint(launched.list()) != want {
		t.Fatalf("a launched stage delivered %v, want %s; the stage said %q", launched.list(), want, readLog(t, driver, handle))
	}
	if log := readLog(t, driver, handle); !strings.Contains(log, "forged into 0") {
		t.Fatalf("the launched stage held a descriptor it could write: %q", log)
	}

	// An allowlist that names no host runs the proxy when its refusals are
	// reported, and reports them.
	empty := newEvents()
	spec.Network, spec.OnRefused = Network{Mode: NetworkAllowlist}, empty.add
	command, cleanup, err = driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("the stage: %v\n%s", err, output)
	}
	cleanup()
	if want := "[{refused.test 443} {refused.test 80}]"; fmt.Sprint(empty.list()) != want {
		t.Fatalf("an empty allowlist delivered %v, want %s", empty.list(), want)
	}

	// A stage with no network, or with no OnRefused, opens no pipe.
	spec.Network = Network{Mode: NetworkNone}
	command, cleanup, err = driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(command.ExtraFiles) != 0 {
		t.Fatal("a stage with no network was given a pipe for refusals")
	}
	cleanup()
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}
	spec.OnRefused = nil
	command, cleanup, err = driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(command.ExtraFiles) != 0 {
		t.Fatal("a stage without OnRefused was given a pipe for refusals")
	}
	cleanup()
}

// TestACommandNeverStartedReleasesItsRefusals checks that the cleanup of a
// command that was never started ends its delivery at once.
func TestACommandNeverStartedReleasesItsRefusals(t *testing.T) {
	driver := seatbelt(t)
	spec := stage(t, t.TempDir(), "/bin/true")
	spec.Network = Network{Mode: NetworkAllowlist, Domains: []string{"allowed.test"}}
	spec.OnRefused = func(string, int) { t.Error("a command never started reported a refusal") }
	_, cleanup, err := driver.Command(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	cleanup()
	if elapsed := time.Since(started); elapsed > refusalFlush/2 {
		t.Fatalf("the cleanup took %v", elapsed)
	}
}
