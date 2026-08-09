const axios = require('axios');
const dns = require('dns').promises;

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { url } = req.body || {};
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Valid URL is required.' });
    }

    let targetUrl = url.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }

    const redirectChain = [];
    let currentUrl = targetUrl;
    let stepCount = 1;

    const client = axios.create({
      maxRedirects: 0, 
      timeout: 5000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) QRShield-Security-Auditor/1.0'
      },
      validateStatus: (status) => status >= 200 && status < 400
    });

    while (stepCount <= 10) {
      redirectChain.push({ step: stepCount, url: currentUrl });

      // SSRF Protection: Prevent unshortening internal/private IP ranges and DNS Rebinding
      try {
        const parsedUrl = new URL(currentUrl);
        const hostname = parsedUrl.hostname;
        
        // Block IPv6 localhost, hex, octal, decimal IP formats and obvious strings
        const ssrfRegex = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|localhost|0\.0\.0\.0|\[::1\]|\[::\]|0x[0-9a-f]+)/i;
        if (ssrfRegex.test(hostname)) {
          return res.status(400).json({ error: 'SSRF Security Protection: Scanning internal/private IP networks is restricted.' });
        }

        // Active DNS Resolution to prevent DNS Rebinding to local IPs
        try {
          const resolved = await dns.resolve4(hostname);
          if (resolved.some(ip => ssrfRegex.test(ip))) {
            return res.status(400).json({ error: 'SSRF Security Protection: Domain resolved to internal/private IP.' });
          }
        } catch (e) {
          // If DNS fails, it might be an IP directly, which is fine if it passed the regex, but let's continue
        }

      } catch (e) {
        return res.status(400).json({ error: 'Invalid URL format.' });
      }

      try {
        const response = await client.get(currentUrl);

        if (response.status >= 300 && response.status < 400 && response.headers.location) {
          let nextUrl = response.headers.location;
          if (nextUrl.startsWith('/')) {
            const parsedCurrent = new URL(currentUrl);
            nextUrl = `${parsedCurrent.protocol}//${parsedCurrent.host}${nextUrl}`;
          }
          currentUrl = nextUrl;
          stepCount++;
        } else {
          // Final destination reached
          break;
        }
      } catch (err) {
        if (err.response && err.response.headers && err.response.headers.location) {
          let nextUrl = err.response.headers.location;
          if (nextUrl.startsWith('/')) {
            const parsedCurrent = new URL(currentUrl);
            nextUrl = `${parsedCurrent.protocol}//${parsedCurrent.host}${nextUrl}`;
          }
          currentUrl = nextUrl;
          stepCount++;
        } else {
          break;
        }
      }
    }

    const isRedirected = redirectChain.length > 1;
    const finalUrl = currentUrl;

    res.json({
      success: true,
      originalUrl: url,
      finalUrl: finalUrl,
      isRedirected: isRedirected,
      hopCount: redirectChain.length,
      redirectChain: redirectChain
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to unshorten URL: ' + error.message,
      originalUrl: (req.body && req.body.url) || ''
    });
  }
};
