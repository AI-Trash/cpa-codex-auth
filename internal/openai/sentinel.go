package openai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"openai-tool/cpa-codex-auth/internal/client"

	"github.com/google/uuid"
)

// SentinelGenerator generates sentinel tokens using pure Go PoW.
type SentinelGenerator struct {
	DeviceID  string
	UserAgent string
	SID       string
}

func NewSentinelGenerator(deviceID string) *SentinelGenerator {
	return &SentinelGenerator{
		DeviceID:  deviceID,
		UserAgent: client.UA,
		SID:       uuid.New().String(),
	}
}

// fnv1a32 computes FNV-1a 32-bit hash with murmurhash3 finalizer.
func fnv1a32(text string) string {
	h := uint32(2166136261)
	for _, ch := range text {
		h ^= uint32(ch)
		h *= 16777619
	}
	h ^= h >> 16
	h *= 2246822507
	h ^= h >> 13
	h *= 3266489909
	h ^= h >> 16
	return fmt.Sprintf("%08x", h)
}

func (s *SentinelGenerator) getConfig() []any {
	now := time.Now()
	// Format date exactly like JS new Date().toString() in Chrome on Windows
	dateStr := now.Format("Mon Jan 02 2006 15:04:05") + " " + now.Format("GMT-0700") + " (" + windowsTimezoneName() + ")"

	// Stable values copied from successful browser captures.
	screenSum := 2400
	heapSize := 4294967296
	hwConcVal := 16

	// Realistic performance.now() — sentinel frame just loaded, typically 500-5000ms
	perfNow := 500.0 + rand.Float64()*4500.0
	timeOrigin := float64(now.UnixMilli()) - perfNow

	// Navigator prototype keys matching Chrome 131 Object.keys(Object.getPrototypeOf(navigator))
	// Format: key + U+2212 (MINUS SIGN) + navigator[key].toString()
	navEntries := []string{
		"vibrate\u2212function vibrate() { [native code] }",
		"javaEnabled\u2212function javaEnabled() { [native code] }",
		"getGamepads\u2212function getGamepads() { [native code] }",
		"sendBeacon\u2212function sendBeacon() { [native code] }",
		"canShare\u2212function canShare() { [native code] }",
		"share\u2212function share() { [native code] }",
		"requestMediaKeySystemAccess\u2212function requestMediaKeySystemAccess() { [native code] }",
		"getInstalledRelatedApps\u2212function getInstalledRelatedApps() { [native code] }",
		"registerProtocolHandler\u2212function registerProtocolHandler() { [native code] }",
		"unregisterProtocolHandler\u2212function unregisterProtocolHandler() { [native code] }",
		"permissions\u2212[object Permissions]",
		"credentials\u2212[object CredentialsContainer]",
		"mediaDevices\u2212[object MediaDevices]",
		"locks\u2212[object LockManager]",
		"clipboard\u2212[object Clipboard]",
		"geolocation\u2212[object Geolocation]",
		"connection\u2212[object NetworkInformation]",
		"storage\u2212[object StorageManager]",
		"mediaCapabilities\u2212[object MediaCapabilities]",
		"userActivation\u2212[object UserActivation]",
		"mediaSession\u2212[object MediaSession]",
		"wakeLock\u2212[object WakeLock]",
		"mimeTypes\u2212[object MimeTypeArray]",
		"plugins\u2212[object PluginArray]",
		"scheduling\u2212[object Scheduling]",
		"gpu\u2212[object GPU]",
		"ink\u2212[object Ink]",
		"hid\u2212[object HID]",
		"usb\u2212[object USB]",
		"bluetooth\u2212[object Bluetooth]",
		"serial\u2212[object Serial]",
		"presentation\u2212[object Presentation]",
		"keyboard\u2212[object Keyboard]",
		"windowControlsOverlay\u2212[object WindowControlsOverlay]",
		"cookieEnabled\u2212true",
		"webdriver\u2212false",
		"pdfViewerEnabled\u2212true",
		fmt.Sprintf("hardwareConcurrency\u2212%d", hwConcVal),
		"maxTouchPoints\u22120",
		"onLine\u2212true",
		"vendor\u2212Google Inc.",
		"productSub\u221220030107",
		"platform\u2212Win32",
		"product\u2212Gecko",
		"userAgent\u2212" + s.UserAgent,
		"language\u2212zh-CN",
		"languages\u2212zh-CN",
	}

	// Random react suffix per call — different "page loads"
	reactSuffix := randomAlphaLower(11)
	docKeys := []string{
		"__reactContainer$" + reactSuffix,
		"__reactFiber$" + reactSuffix,
		"__reactProps$" + reactSuffix,
		"__reactEvents$" + reactSuffix,
		"__reactInternalInstance$" + reactSuffix,
		"__reactListeners$" + reactSuffix,
	}

	winKeys := []string{
		"getComputedStyle", "getSelection", "matchMedia", "requestAnimationFrame",
		"cancelAnimationFrame", "fetch", "setTimeout", "clearTimeout",
		"setInterval", "clearInterval", "requestIdleCallback",
		"cancelIdleCallback", "createImageBitmap", "structuredClone",
		"postMessage", "addEventListener", "removeEventListener",
		"dispatchEvent", "atob", "btoa", "reportError",
		"queueMicrotask", "focus", "blur", "close",
		"open", "stop", "print", "alert", "confirm", "prompt",
		"scroll", "scrollTo", "scrollBy", "resizeTo", "resizeBy",
		"moveTo", "moveBy", "find", "getScreenDetails",
		"onunload", "onbeforeunload", "onpagehide", "onpageshow",
		"ondeviceorientation", "ondevicemotion", "onhashchange",
		"onpopstate", "onmessage", "onmessageerror",
		"onstorage", "ononline", "onoffline", "onresize",
		"onscroll", "onfocus", "onblur", "onerror",
		"onload", "oncontextmenu", "ondragover", "ondrop",
		"onkeydown", "onkeyup", "onkeypress",
		"onclick", "ondblclick", "onmousedown", "onmouseup",
		"onmousemove", "onmouseover", "onmouseout",
		"onpointerdown", "onpointerup", "onpointermove",
		"ontouchstart", "ontouchend", "ontouchmove",
		"onwheel", "onanimationend", "onanimationstart",
		"ontransitionend", "onsubmit", "oninput", "onchange",
		"SentinelSDK", "chrome", "navigation", "scheduler",
		"crossOriginIsolated", "originAgentCluster",
		"webkitRequestAnimationFrame", "webkitCancelAnimationFrame",
	}

	// Match real SDK getConfig() structure exactly: 25 elements
	return []any{
		screenSum,      // [0] screen.width + screen.height
		dateStr,        // [1] "" + new Date
		heapSize,       // [2] performance.memory.jsHeapSizeLimit
		rand.Float64(), // [3] Math.random() — replaced: nonce during PoW, 1 for requirements
		s.UserAgent,    // [4] navigator.userAgent
		"https://sentinel.openai.com/backend-api/sentinel/sdk.js", // [5] R(document.scripts.map(s=>s.src)) — pre-redirect URL
		nil,                                    // [6] scripts matching c/[^/]*/_  ||  documentElement.getAttribute("data-build")
		"zh-CN",                                // [7] navigator.language
		"zh-CN",                                // [8] navigator.languages.join(",")
		10,                                     // [9] Math.random() — replaced with elapsed ms during PoW
		navEntries[rand.Intn(len(navEntries))], // [10] T(): random navigator prototype key + "−" + toString()
		docKeys[rand.Intn(len(docKeys))],       // [11] R(Object.keys(document))
		winKeys[rand.Intn(len(winKeys))],       // [12] R(Object.keys(window))
		perfNow,                                // [13] performance.now()
		s.SID,                                  // [14] this.sid (UUID v4)
		"",                                     // [15] [...new URLSearchParams(location.search).keys()].join(",")
		hwConcVal,                              // [16] navigator.hardwareConcurrency
		timeOrigin,                             // [17] performance.timeOrigin
		0, 0, 0, 0, 0, 0, 0,                    // [18-24] Number("ai"|"createPRNG"|"cache"|"data"|"solana"|"dump"|"InstallTrigger" in window)
	}
}

// windowsTimezoneName returns the English timezone display name matching Chrome's Date.toString() output.
func windowsTimezoneName() string {
	_, offset := time.Now().Zone()
	hours := offset / 3600
	// Map UTC offset to Windows/Chrome English timezone name
	names := map[int]string{
		-12: "Dateline Standard Time",
		-11: "Samoa Standard Time",
		-10: "Hawaiian Standard Time",
		-9:  "Alaskan Standard Time",
		-8:  "Pacific Standard Time",
		-7:  "Mountain Standard Time",
		-6:  "Central Standard Time",
		-5:  "Eastern Standard Time",
		-4:  "Atlantic Standard Time",
		-3:  "SA Eastern Standard Time",
		0:   "GMT Standard Time",
		1:   "W. Europe Standard Time",
		2:   "E. Europe Standard Time",
		3:   "Russian Standard Time",
		4:   "Arabian Standard Time",
		5:   "West Asia Standard Time",
		6:   "Central Asia Standard Time",
		7:   "SE Asia Standard Time",
		8:   "China Standard Time",
		9:   "Tokyo Standard Time",
		10:  "AUS Eastern Standard Time",
		11:  "Central Pacific Standard Time",
		12:  "New Zealand Standard Time",
	}
	if name, ok := names[hours]; ok {
		return name
	}
	return "Coordinated Universal Time"
}

func randomAlphaLower(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + rand.Intn(26))
	}
	return string(b)
}

func b64Encode(data any) string {
	// Use encoder with SetEscapeHTML(false) to match JS JSON.stringify exactly
	// (Go's json.Marshal escapes <, >, & as \u003c etc. by default)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
	// json.Encoder.Encode appends a newline — strip it
	raw := buf.Bytes()
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func (s *SentinelGenerator) GenerateRequirementsToken() string {
	config := s.getConfig()
	config[3] = 1
	config[9] = rand.Intn(45) + 5
	return "gAAAAAC" + b64Encode(config)
}

func (s *SentinelGenerator) GeneratePoWToken(seed, difficulty string) string {
	if difficulty == "" {
		difficulty = "0"
	}
	startTime := time.Now()
	config := s.getConfig()
	diffLen := len(difficulty)
	// fnv1a32 always returns 8 hex chars via fmt.Sprintf("%08x", ...); clamp
	// any malformed (longer-than-8) difficulty so the slice below cannot panic.
	if diffLen > 8 {
		diffLen = 8
	}
	for nonce := 0; nonce < 500000; nonce++ {
		config[3] = nonce
		config[9] = int(time.Since(startTime).Milliseconds())
		encoded := b64Encode(config)
		hash := fnv1a32(seed + encoded)
		if hash[:diffLen] <= difficulty {
			return "gAAAAAB" + encoded + "~S"
		}
	}
	return "gAAAAABwQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + b64Encode("None")
}
