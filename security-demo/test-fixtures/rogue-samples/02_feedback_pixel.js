// INERT detector test — pixel-beacon sink. Benign payload (feedback text).
// Shape: form field .value -> variable -> assigned to Image().src (GET beacon).

const feedback = document.getElementById('feedback').value;   // SOURCE (.value)
const beacon = new Image();
beacon.src = 'https://metrics.example/p?d=' + encodeURIComponent(feedback); // SINK (.src)
