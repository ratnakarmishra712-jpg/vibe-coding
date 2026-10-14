// TEST FIXTURE for sast-scan.js — benign-but-flaggable.
//
// This is NOT malware and NOT a credential stealer. It reads a THEME preference
// and a display NICKNAME and sends them to an analytics host. That's a mundane
// (if privacy-questionable) real-world pattern. Its job here is to exercise the
// scanner's taint engine: source -> variable -> network sink, to an external
// host. The reviewer's lesson: a flagged flow is a LEAD, and triage decides
// whether the flow is acceptable (here: yes — add the host to --allow).

// SOURCE: localStorage read (scanner treats storage reads as secret-sources,
// because tokens often live here — even though this value is just a theme).
const theme = localStorage.getItem('theme') || 'light';

// SOURCE: a form field .value (a nickname box — not a password).
const nick = document.getElementById('nickname').value;

// taint propagation through a plain variable + object
const payload = JSON.stringify({ theme: theme, nick: nick });

// SINK: fetch to an EXTERNAL host -> scanner should rate this HIGH
// (tainted data leaving to a non-allowlisted origin).
fetch('https://analytics.example/collect', { method: 'POST', body: payload });

// SINK: sendBeacon with the same tainted payload (also HIGH).
navigator.sendBeacon('https://analytics.example/beacon', payload);

// A clean call with no tainted data and a first-party relative URL:
// scanner should NOT flag this.
fetch('/api/health');
