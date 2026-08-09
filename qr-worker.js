importScripts('https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js');

self.addEventListener('message', function(e) {
  const { data, width, height } = e.data;
  
  if (!data) return;

  // Perform standard QR decoding
  let code = jsQR(data, width, height);
  
  if (!code) {
    // Fallback: Invert color pass for dark-mode QRs
    for (let i = 0; i < data.length; i += 4) {
      data[i] = 255 - data[i];
      data[i + 1] = 255 - data[i + 1];
      data[i + 2] = 255 - data[i + 2];
    }
    code = jsQR(data, width, height);
  }

  // Return the result
  if (code && code.data) {
    self.postMessage({ success: true, payload: code.data });
  } else {
    self.postMessage({ success: false });
  }
});
