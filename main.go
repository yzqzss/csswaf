package main

import (
	cryptorand "crypto/rand"
	_ "embed"
	"encoding/base64"
	"flag"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

//go:embed empty.gif
var emptyGIF []byte

var HoneypotImg = []string{"G.html", "H.txt", "I.sitemap", "J.xml", "article", "content", "user", "history", "O", "P", "Q"}
var Sequence = []string{"A", "B", "C", "D", "E", "F"}

// SessionTracker keeps track of image loading sequences for each session
type SessionTracker struct {
	sequences *ttlcache.Cache[string, []string] // Maps session ID to sequence of loaded images
	expected  *ttlcache.Cache[string, []string] // Maps session ID to expected sequence
	validated *ttlcache.Cache[string, bool]     // Maps session ID to validation status
}

var cssAnimationTS = 3.5
var showSessionStatusTS = 4.0
var pageRefreshTS = 5.5

// NewSessionTracker creates a new session tracker
func NewSessionTracker(ttl time.Duration) *SessionTracker {
	// Create caches with 1-hour TTL
	sequences := ttlcache.New(
		ttlcache.WithTTL[string, []string](ttl),
		ttlcache.WithDisableTouchOnHit[string, []string](),
	)
	expected := ttlcache.New(
		ttlcache.WithTTL[string, []string](ttl),
		ttlcache.WithDisableTouchOnHit[string, []string](),
	)
	validated := ttlcache.New(
		ttlcache.WithTTL[string, bool](ttl),
		ttlcache.WithDisableTouchOnHit[string, bool](),
	)

	// Start the cache cleanup processes
	go sequences.Start()
	go expected.Start()
	go validated.Start()

	return &SessionTracker{
		sequences: sequences,
		expected:  expected,
		validated: validated,
	}
}

// AddImageLoad records an image load for a session
func (st *SessionTracker) AddImageLoad(sessionID, imageID string) {
	var sequence []string
	sequenceTTL := st.sequences.Get(sessionID)
	if sequenceTTL != nil {
		sequence = sequenceTTL.Value()
	}
	if slices.Contains(HoneypotImg, imageID) {
		slog.Warn("Honeypot image loaded",
			"sessionID", sessionID[:8],
			"imageID", imageID,
		)
		sequence = []string{"Honeypot_placeholder"}
		st.sequences.Set(sessionID, sequence, ttlcache.DefaultTTL)
		return
	}

	sequence = append(sequence, imageID)
	slog.Info("Image loaded",
		"sessionID", sessionID[:8],
		"imageID", imageID,
		"sequence", sequence,
	)
	st.sequences.Set(sessionID, sequence, ttlcache.DefaultTTL)

	// Check if sequence matches expected sequence
	expectedSeqTTL := st.expected.Get(sessionID)
	var expectedSeq []string
	if expectedSeqTTL != nil {
		expectedSeq = expectedSeqTTL.Value()
	}
	if expectedSeq != nil && len(sequence) == len(expectedSeq) {
		match := true
		for i := range sequence {
			if (sequence)[i] != (expectedSeq)[i] {
				match = false
				break
			}
		}
		st.validated.Set(sessionID, match, ttlcache.DefaultTTL)
		slog.Info("Session validation result",
			"sessionID", sessionID[:8],
			"validated", match,
			"expected", expectedSeq,
			"received", sequence,
		)
	}
}

// SetExpectedSequence sets the expected sequence for a session
func (st *SessionTracker) SetExpectedSequence(sessionID string, sequence []string) {
	st.expected.Set(sessionID, sequence, ttlcache.DefaultTTL)
	st.sequences.Set(sessionID, []string{}, ttlcache.DefaultTTL) // Reset sequence
	slog.Info("Set expected sequence for session",
		"sessionID", sessionID[:8],
		"sequence", sequence,
	)
}

// IsValidated checks if a session has been validated
func (st *SessionTracker) IsValidated(sessionID string) bool {
	validated := st.validated.Get(sessionID)
	if validated != nil {
		return validated.Value()
	}
	return false
}

// GenerateSessionID creates a random session ID
func GenerateSessionID() (string, error) {
	b := make([]byte, 16)
	_, err := cryptorand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CSSWAF is our main proxy that implements the CSS-based WAF
type CSSWAF struct {
	tracker        *SessionTracker
	targetURL      *url.URL
	proxy          *httputil.ReverseProxy
	cookieName     string
	cookieLifetime time.Duration
}

// NewCSSWAF creates a new CSS-based WAF
func NewCSSWAF(targetURL string, ttl time.Duration) (*CSSWAF, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	csswaf := &CSSWAF{
		tracker:        NewSessionTracker(ttl),
		targetURL:      target,
		cookieName:     "csswaf_session",
		cookieLifetime: 1 * time.Hour,
	}

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize director to preserve host header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	// Add response modifier to inject our CSS
	// proxy.ModifyResponse = csswaf.wafResponse

	csswaf.proxy = proxy
	return csswaf, nil
}

// shuffle returns a shuffled copy of the input slice
func shuffle(input []string) []string {
	perm := mathrand.Perm(len(input))
	for i, v := range perm {
		input[v], input[i] = input[i], input[v]
	}
	return input
}

// handleImageRequest processes requests for our tracking images
func (waf *CSSWAF) handleImageRequest(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}

	imageID := parts[len(parts)-1]

	// Get session ID from query parameter
	sessionID := r.URL.Query().Get("sid")
	if sessionID == "" {
		http.NotFound(w, r)
		return
	}

	// Record this image load
	waf.tracker.AddImageLoad(sessionID, imageID)

	// Serve a tiny transparent 1x1 pixel GIF
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write(emptyGIF)
	slog.Info("Served tracking image",
		"sessionID", sessionID[:8],
		"imageID", imageID,
	)
}

func (waf *CSSWAF) renderWafResponse(w http.ResponseWriter, r *http.Request) {
	// Generate a new session ID
	sessionID, err := GenerateSessionID()
	if err != nil {
		slog.Error("Failed to generate session ID", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	cookie := &http.Cookie{
		Name:     waf.cookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(waf.cookieLifetime),
	}
	http.SetCookie(w, cookie)

	// random reordering
	expectedSequence := shuffle(Sequence)
	waf.tracker.SetExpectedSequence(sessionID, expectedSequence)

	newBody := `<!DOCTYPE html>
<html>
<head>
<link rel="icon" href="data:image/png;base64,iVBORw0KGgo="> <!-- empty favicon to prevent browser requests -->
<meta http-equiv="refresh" content="` + strconv.FormatFloat(pageRefreshTS, 'f', -1, 64) + `">
<style>
.honeypot {` + func() string {
		lines := []string{}
		for _, img := range HoneypotImg {
			lines = append(lines, "content: url('/_csswaf/img/"+img+"?sid="+sessionID+"');")
			break // TEST: only one honeypot css image
		}
		return strings.Join(lines, "\n")
	}() + `
}
@keyframes csswaf-load {
  ` + func(expectedSequence []string) string {
		lines := []string{}
		for i, img := range expectedSequence {
			f := float64(i) / float64(len(expectedSequence))
			lines = append(lines, strconv.Itoa(int(f*100))+`% { content: url('/_csswaf/img/`+img+`?sid=`+sessionID+`'); }`)
		}
		lines = shuffle(lines)
		return strings.Join(lines, "\n")
	}(expectedSequence) + `
}
.csswaf-hidden {
width: 1px;
height: 1px;
position: absolute;
top: 0px;
left: 0px;
animation: csswaf-load ` + strconv.FormatFloat(cssAnimationTS, 'f', -1, 64) + `s linear infinite;
}

/* center the content */
body {
display: flex;
justify-content: center;
align-items: center;
height: 100vh;
margin: 0;
font-family: Arial, sans-serif;
background-color: #f9f5d7;
}

.container {
text-align: center;
}

/* copied from anubis */
.lds-roller,
.lds-roller div,
.lds-roller div:after {
	box-sizing: border-box;
}

.lds-roller {
	display: inline-block;
	position: relative;
	width: 80px;
	height: 80px;
}

.lds-roller div {
	animation: lds-roller 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
	transform-origin: 40px 40px;
}

.lds-roller div:after {
	content: " ";
	display: block;
	position: absolute;
	width: 7.2px;
	height: 7.2px;
	border-radius: 50%;
	background: currentColor;
	margin: -3.6px 0 0 -3.6px;
}

.lds-roller div:nth-child(1) {
	animation-delay: -0.036s;
}

.lds-roller div:nth-child(1):after {
	top: 62.62742px;
	left: 62.62742px;
}

.lds-roller div:nth-child(2) {
	animation-delay: -0.072s;
}

.lds-roller div:nth-child(2):after {
	top: 67.71281px;
	left: 56px;
}

.lds-roller div:nth-child(3) {
	animation-delay: -0.108s;
}

.lds-roller div:nth-child(3):after {
	top: 70.90963px;
	left: 48.28221px;
}

.lds-roller div:nth-child(4) {
	animation-delay: -0.144s;
}

.lds-roller div:nth-child(4):after {
	top: 72px;
	left: 40px;
}

.lds-roller div:nth-child(5) {
	animation-delay: -0.18s;
}

.lds-roller div:nth-child(5):after {
	top: 70.90963px;
	left: 31.71779px;
}

.lds-roller div:nth-child(6) {
	animation-delay: -0.216s;
}

.lds-roller div:nth-child(6):after {
	top: 67.71281px;
	left: 24px;
}

.lds-roller div:nth-child(7) {
	animation-delay: -0.252s;
}

.lds-roller div:nth-child(7):after {
	top: 62.62742px;
	left: 17.37258px;
}

.lds-roller div:nth-child(8) {
	animation-delay: -0.288s;
}

.lds-roller div:nth-child(8):after {
	top: 56px;
	left: 12.28719px;
}

@keyframes lds-roller {
	0% {
	transform: rotate(0deg);
	}

	100% {
	transform: rotate(360deg);
	}
}


.message {
	font-size: 18px;
	color: #333;
	margin-top: 10px;
}

/* Image switching animation */

.pensive {
	animation: show-pensive ` + strconv.FormatFloat(showSessionStatusTS, 'f', -1, 64) + `s steps(1, end) forwards;
}

.mysession {
	animation: show-mysession ` + strconv.FormatFloat(showSessionStatusTS, 'f', -1, 64) + `s steps(1, end) forwards;
	opacity: 0; /* hide initially */
}

@keyframes show-pensive {
	0% {
		opacity: 1;
		content: url('/_csswaf/res/pensive.webp');
	}
	100% {
		opacity: 0;
	}
}

@keyframes show-mysession {
	0% {
		opacity: 0;
	}
	100% {
		opacity: 1;
		content: url('/_csswaf/res/sessionstatus.webp');
	}
}
.honeya {
	display: none;
	width: 0px;
	height: 0px;
	position: absolute;
	top: -99px;
	left: -99px;
}
  </style>
</head>
<body>
` + func() string {
		lines := []string{}
		for _, img := range HoneypotImg {
			lines = append(lines, "<a href='/_csswaf/img/"+img+"?sid="+sessionID+"' class='honeya'>View Content</a>")
		}
		return strings.Join(lines, "\n")
	}() + `
<div class="csswaf-hidden"></div>
<div class="container">
	<div class="pensive"></div>
	<div class="mysession"></div>
	<p class="message">...</p>
	<div id="spinner" class="lds-roller">
		<div></div>
		<div></div>
		<div></div>
		<div></div>
		<div></div>
		<div></div>
		<div></div>
		<div></div>
	</div>` + func() string {
		lines := []string{}
		for _, img := range shuffle(HoneypotImg) {
			// put the honeypot to unseen positions, enable lazy loading.
			// If user loads the honeypot, BOOM! It's a bot.
			lines = append(lines, `<img src="/_csswaf/img/`+img+`?sid=`+sessionID+`" style="width: 0px; height: 0px; position: absolute; top: -9999px; left: -9999px;" loading="lazy">`)
		}
		return strings.Join(lines, "\n")
	}() + `
	<p class="message">Challenge: please wait for ` + strconv.FormatFloat(pageRefreshTS, 'f', -1, 64) + ` seconds</p>
	<p class="message">This Challenge is NoJS friendly</p>
	<p class="message">Session ID: ` + sessionID + `</p>
	<footer>
		<p>Powered by <a href="https://github.com/yzqzss/csswaf">CSSWAF</a></p>
	</footer>
</div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(newBody)))
	// no-cache
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")

	// 403 Forbidden
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(newBody))

	slog.Info("Injected CSS challenge",
		"sessionID", sessionID[:8],
		"contentLength", len(newBody),
	)
}

//go:embed pensive.webp
var pensivewebp []byte

//go:embed happy.webp
var happywebp []byte

//go:embed sad.webp
var sadwebp []byte

var filemap = map[string][]byte{
	"pensive.webp": pensivewebp,
	"happy.webp":   happywebp,
	"sad.webp":     sadwebp,
}

// ServeHTTP implements the http.Handler interface
func (waf *CSSWAF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if this is a request for one of our tracking images
	if strings.HasPrefix(r.URL.Path, "/_csswaf/res/") {
		fileName := r.URL.Path[len("/_csswaf/res/"):]
		if data, exists := filemap[fileName]; exists {
			w.Header().Set("Content-Type", "image/webp")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			_, _ = w.Write(data)
		} else {
			//
		}

		if fileName == "sessionstatus.webp" {
			cookie, err := r.Cookie(waf.cookieName)
			if err == nil {
				sessionID := cookie.Value
				w.Header().Set("Content-Type", "image/webp")
				// no-cache
				w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
				w.Header().Set("Pragma", "no-cache")

				if waf.tracker.IsValidated(sessionID) {
					w.Header().Set("Content-Length", strconv.Itoa(len(happywebp)))
					_, _ = w.Write(happywebp)
					return
				} else {
					w.Header().Set("Content-Length", strconv.Itoa(len(sadwebp)))
					_, _ = w.Write(sadwebp)
					return
				}
			}
		}
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/_csswaf/img/") {
		waf.handleImageRequest(w, r)
		return
	}

	// bypass non-browser user-agent
	userAgent := r.Header.Get("User-Agent")
	if !strings.Contains(userAgent, "Mozilla") {
		slog.Info("Non-browser user-agent, proxying request",
			"userAgent", userAgent,
			"url", r.URL.String(),
		)
		waf.proxy.ServeHTTP(w, r)
		return
	}

	// bypass RSS requests
	pathLow := strings.ToLower(r.URL.Path)
	if strings.Contains(pathLow, "rss") || strings.Contains(pathLow, "feed") || strings.Contains(pathLow, "atom") {
		slog.Info("RSS request, proxying request",
			"url", r.URL.String(),
		)
		waf.proxy.ServeHTTP(w, r)
		return
	}

	// bypass .txt requests
	if strings.HasSuffix(pathLow, ".txt") {
		slog.Info("Text file request, proxying request",
			"url", r.URL.String(),
		)
		waf.proxy.ServeHTTP(w, r)
		return
	}

	// Check for session cookie
	cookie, err := r.Cookie(waf.cookieName)
	if err == nil {
		// We have a session, check if it's validated
		sessionID := cookie.Value
		if waf.tracker.IsValidated(sessionID) {
			// Session is validated, proxy the request
			slog.Info("Validated session, proxying request",
				"sessionID", sessionID[:8],
				"url", r.URL.String(),
			)
			waf.proxy.ServeHTTP(w, r)
			return
		}
	}

	// No valid session, proxy the request anyway
	// Our ModifyResponse will inject the challenge if needed
	slog.Info("No valid session, create challenge",
		"url", r.URL.String(),
	)
	waf.renderWafResponse(w, r)
}

var target = flag.String("target", "http://localhost:8080", "target to reverse proxy to. ('test' to run a test server at :8080)")
var bind = flag.String("bind", ":8081", "address to bind to")
var ttl = flag.Duration("ttl", 1*time.Hour, "session expiration time")

func testServer() {
	// Create a test server
	newhttp := http.NewServeMux()
	newhttp.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("Hello, world!"))
	})
	slog.Error(http.ListenAndServe(":8080", newhttp).Error())
}

func main() {
	flag.Parse()
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)

	if *target == "test" {
		// Run a test server at :8080
		slog.Info("Running test server at :8080")
		go testServer()
		*target = "http://localhost:8080"
	}

	// Create CSSWAF instance
	waf, err := NewCSSWAF(*target, *ttl)
	if err != nil {
		slog.Error("Failed to create CSSWAF", "error", err)
		return
	}

	http.Handle("/", waf)
	slog.Info("Listening on", "address", *bind)
	slog.Error(http.ListenAndServe(*bind, nil).Error())
}
