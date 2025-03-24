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
	"sync"
	"time"
)

// en:
// css puts the lazy-loaded hidden images (empty.gif) in order in various out-of-view positions.
// css lets the browser load these images one by one.
// The backend measures the loading order, and the order matches to pass (set-cookie)

//go:embed empty.gif
var emptyGIF []byte

var HoneypotImg = []string{"K", "L", "M", "N", "O", "P", "Q", "R", "S", "T"}
var Sequence = []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}

// SessionTracker keeps track of image loading sequences for each session
type SessionTracker struct {
	sequences map[string][]string // Maps session ID to sequence of loaded images
	expected  map[string][]string // Maps session ID to expected sequence
	validated map[string]bool     // Maps session ID to validation status
	mu        sync.Mutex
}

// NewSessionTracker creates a new session tracker
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		sequences: make(map[string][]string),
		expected:  make(map[string][]string),
		validated: make(map[string]bool),
	}
}

// AddImageLoad records an image load for a session
func (st *SessionTracker) AddImageLoad(sessionID, imageID string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if _, exists := st.sequences[sessionID]; !exists {
		st.sequences[sessionID] = []string{}
	}

	if slices.Contains(HoneypotImg, imageID) {
		slog.Warn("Honeypot image loaded",
			"sessionID", sessionID[:8],
			"imageID", imageID,
		)
		st.sequences[sessionID] = []string{"Honeypot_placeholder"}
		return
	}

	st.sequences[sessionID] = append(st.sequences[sessionID], imageID)

	// Check if sequence matches expected sequence
	if expectedSeq, exists := st.expected[sessionID]; exists {
		currentSeq := st.sequences[sessionID]

		// Check if we have enough loaded images to make a decision
		if len(currentSeq) == len(expectedSeq) {
			match := true
			for i := range currentSeq {
				if currentSeq[i] != expectedSeq[i] {
					match = false
					break
				}
			}
			st.validated[sessionID] = match
			slog.Info("Session validation result",
				"sessionID", sessionID[:8],
				"validated", match,
				"expected", expectedSeq,
				"received", currentSeq,
			)
		}
	}
}

// SetExpectedSequence sets the expected sequence for a session
func (st *SessionTracker) SetExpectedSequence(sessionID string, sequence []string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.expected[sessionID] = sequence
	st.sequences[sessionID] = []string{} // Reset sequence
	slog.Info("Set expected sequence for session",
		"sessionID", sessionID[:8],
		"sequence", sequence,
	)
}

// IsValidated checks if a session has been validated
func (st *SessionTracker) IsValidated(sessionID string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.validated[sessionID]
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
func NewCSSWAF(targetURL string) (*CSSWAF, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	csswaf := &CSSWAF{
		tracker:        NewSessionTracker(),
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
<meta http-equiv="refresh" content="6">
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
animation: csswaf-load 3s linear infinite;
}

/* center the content */
body {
display: flex;
justify-content: center;
align-items: center;
height: 100vh;
margin: 0;
font-family: Arial, sans-serif;
background-color: #f9f9f9;
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
	animation: show-pensive 4s steps(1, end) forwards;
}

.mysession {
	animation: show-mysession 4s steps(1, end) forwards;
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
  </style>
</head>
<body>
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
			lines = append(lines, `<img src="/_csswaf/img/`+img+`?sid=`+sessionID+`" style="width: 1px; height: 1px; position: absolute; top: -999px; left: -999px;" loading="lazy">`)
		}
		return strings.Join(lines, "\n")
	}() + `
	<p class="message">Challenge: please wait for 5 seconds</p>
	<p class="message">This Challenge is NoJS friendly</p>
	<p class="message">Session ID: ` + sessionID + `</p>
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

var target = flag.String("target", "http://localhost:8080", "target to reverse proxy to")
var bind = flag.String("bind", ":8081", "address to bind to")

func main() {
	flag.Parse()
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)

	// Create CSSWAF instance
	waf, err := NewCSSWAF(*target)
	if err != nil {
		slog.Error("Failed to create CSSWAF", "error", err)
		return
	}

	http.Handle("/", waf)
	slog.Info("Listening on", "address", *bind)
	slog.Error(http.ListenAndServe(*bind, nil).Error())
}
