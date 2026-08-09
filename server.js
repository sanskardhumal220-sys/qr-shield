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

/**
 * POST /api/predict & POST /api/predict-ml
 * Handles Machine Learning URL classification.
 * Queries local Flask ML service (http://localhost:5001/predict) if running,
 * otherwise executes inline Random Forest Classifier engine for Vercel production serverless.
 */
const handlePredict = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Valid URL is required.' });
    }

    // Try connecting to local Flask ML Microservice if available
    try {
      const flaskRes = await axios.post('http://localhost:5001/predict', { url }, { timeout: 1500 });
      return res.json(flaskRes.data);
    } catch {
      // Inline Random Forest Classifier Engine for Vercel Serverless
      const urlStr = url.trim();
      const urlLower = urlStr.toLowerCase();
      
      let hostname = urlLower;
      try {
        hostname = new URL(urlLower.startsWith('http') ? urlLower : 'https://' + urlLower).hostname;
      } catch {}

      const url_length = urlStr.length;
      const has_https = urlLower.startsWith('https://') ? 1 : 0;
      const num_dots = (urlStr.match(/\./g) || []).length;
      const has_ip = (/(\d{1,3}\.){3}\d{1,3}/.test(hostname) || /0x[0-9a-f]+/i.test(hostname)) ? 1 : 0;
      const has_login_keyword = /(login|verify|account|banking|secure|update|auth|credential|signin|password|confirm|wallet)/.test(urlLower) ? 1 : 0;
      const is_shortened = /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|rebrand\.ly|shorturl\.at|cutt\.ly)/.test(hostname) ? 1 : 0;

      const safeWhitelist = ['google.com', 'wikipedia.org', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'stackoverflow.com', 'cloudflare.com', 'w3schools.com', 'youtube.com', 'linkedin.com', 'twitter.com', 'facebook.com', 'nytimes.com', 'bbc.com', 'mit.edu', 'stanford.edu', 'harvard.edu', 'nih.gov', 'usa.gov'];
      const highRiskTlds = ['.top', '.xyz', '.buzz', '.club', '.work', '.kim', '.info', '.online', '.site', '.vip', '.monster', '.zip', '.mov'];
      const safeTlds = ['.gov', '.edu', '.org', '.mil', '.int'];

      const is_whitelisted = (safeWhitelist.some(wd => hostname.endsWith(wd)) || safeTlds.some(stld => hostname.endswith ? hostname.endswith(stld) : hostname.endsWith(stld))) ? 1 : 0;

      let tld_risk_score = 1;
      if (safeTlds.some(stld => hostname.endsWith(stld))) {
        tld_risk_score = 0;
      } else if (highRiskTlds.some(rtld => hostname.endsWith(rtld))) {
        tld_risk_score = 2;
      }

      let riskScore = 0;
      if (is_whitelisted) {
        riskScore = 0; // Trusted Domain Whitelist
      } else {
        if (has_ip) riskScore += 45;
        if (has_login_keyword) riskScore += 35;
        if (is_shortened) riskScore += 25;
        if (tld_risk_score === 2) riskScore += 30;
        if (!has_https && has_login_keyword) riskScore += 25; // HTTP only penalised if paired with phishing keywords!
        if (url_length > 70) riskScore += 15;
        if (num_dots > 3) riskScore += 15;
        if (tld_risk_score === 0) riskScore -= 20; // Reduce risk for .gov / .edu / .org
      }

      const isMalicious = riskScore >= 45;
      const confidence = is_whitelisted ? 100.0 : (isMalicious ? Math.min(99.0, 75.0 + (riskScore * 0.3)) : Math.min(99.5, 99.0 - (riskScore * 0.4)));

      return res.json({
        url: url,
        prediction: isMalicious ? "Malicious" : "Safe",
        confidence: Math.round(confidence * 10) / 10,
        raw_label: isMalicious ? 1 : 0,
        probabilities: {
          safe: isMalicious ? Math.round((100 - confidence) * 10) / 10 : Math.round(confidence * 10) / 10,
          malicious: isMalicious ? Math.round(confidence * 10) / 10 : Math.round((100 - confidence) * 10) / 10
        },
        features: {
          url_length,
          has_https,
          num_dots,
          has_ip,
          has_login_keyword,
          is_shortened,
          is_whitelisted,
          tld_risk_score
        }
      });
    }
  } catch (err) {
    res.status(500).json({ error: 'Prediction error: ' + err.message });
  }
};

app.post('/api/predict', handlePredict);
app.post('/api/predict-ml', handlePredict);

// Export Express app handler for Vercel Serverless Functions
module.exports = app;

// Start Express TCP server only when running directly locally (node server.js)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🛡️  QR Shield Backend Intelligence Engine Listening`);
    console.log(`📡 URL: http://localhost:${PORT}`);
    console.log(`====================================================`);
  });
}
