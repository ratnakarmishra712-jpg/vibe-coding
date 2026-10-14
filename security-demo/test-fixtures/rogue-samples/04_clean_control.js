// INERT control — should produce ZERO findings.
// Reads storage but only uses it LOCALLY, and makes a first-party request that
// carries no secret data. No source -> external-sink flow exists here.

const theme = localStorage.getItem('theme') || 'light';   // SOURCE, but...
document.body.dataset.theme = theme;                       // ...stays local (no sink)

fetch('/api/news');                                        // first-party, no tainted data
