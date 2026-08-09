/**
 * QR Shield - Node.js Express Backend API Server
 * Provides server-side redirect unshortening, DNS resolution, and threat intelligence endpoints.
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const dns = require('dns').promises;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static frontend files from current directory
app.use(express.static(__dirname));

/**
 * GET /api/health
 * Health check status endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    service: 'QR Shield Backend Threat Intelligence Engine',
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /api/unshorten
 * Server-side URL Redirect Tracer (unshortens bit.ly, tinyurl, t.co, etc.)
 * Bypasses client-side browser CORS restrictions.
 */
app.post('/api/unshorten', async (req, res) => {
  try {
    const { url } = req.body;
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

    // Custom axios instance with manual redirect tracking
    const client = axios.create({
      maxRedirects: 0, // Intercept redirects manually
      timeout: 5000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) QRShield-Security-Auditor/1.0'
      },
      validateStatus: (status) => status >= 200 && status < 400
    });

    while (stepCount <= 10) {
      redirectChain.push({ step: stepCount, url: currentUrl });

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
      originalUrl: req.body.url
    });
  }
});

/**
 * POST /api/check-domain
 * Server-side DNS resolution & Threat Intelligence Probe
 */
app.post('/api/check-domain', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required.' });
    }

    const cleanDomain = domain.replace(/^(https?:\/\/)/, '').split('/')[0].split(':')[0];
    
    let resolvedIps = [];
    let mxRecords = [];
    let dnsValid = false;

    try {
      resolvedIps = await dns.resolve4(cleanDomain);
      dnsValid = true;
    } catch {
      dnsValid = false;
    }

    try {
      mxRecords = await dns.resolveMx(cleanDomain);
    } catch {
      mxRecords = [];
    }

    res.json({
      success: true,
      domain: cleanDomain,
      dnsValid: dnsValid,
      resolvedIps: resolvedIps,
      hasMailServer: mxRecords.length > 0,
      mxCount: mxRecords.length
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'DNS inspection failed: ' + error.message
    });
  }
});

// Start Express Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🛡️  QR Shield Backend Intelligence Engine Listening`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`====================================================`);
});
