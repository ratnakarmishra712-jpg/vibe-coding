// INERT detector test — WebSocket sink. Benign payload (shopping cart).
// Shape: storage read -> variable -> WebSocket.send to an external host.

const cart = localStorage.getItem('cartItems');      // SOURCE (storage read)
const body = JSON.stringify({ cart: cart, ts: Date.now() });

const ws = new WebSocket('wss://collector.example/ingest');  // external endpoint
ws.onopen = () => ws.send(body);                      // SINK (.send of tainted data)
