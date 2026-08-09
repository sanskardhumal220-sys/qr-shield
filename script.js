/**
 * QR Shield - AI Quishing Detector
 * Main Application Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Element References ---
  const dropZone = document.getElementById('dropZone');
  const dropZoneContent = document.getElementById('dropZoneContent');
  const fileInput = document.getElementById('fileInput');
  const browseBtn = document.getElementById('browseBtn');
  const previewContainer = document.getElementById('previewContainer');
  const qrPreview = document.getElementById('qrPreview');
  const radarOverlay = document.getElementById('radarOverlay');
  const changeImgBtn = document.getElementById('changeImgBtn');
  const errorBanner = document.getElementById('errorBanner');
  const errorMessage = document.getElementById('errorMessage');

  const emptyState = document.getElementById('emptyState');
  const resultContent = document.getElementById('resultContent');
  const resultCard = document.getElementById('resultCard');

  const riskBadge = document.getElementById('riskBadge');
  const riskIcon = document.getElementById('riskIcon');
  const riskText = document.getElementById('riskText');
  const meterScore = document.getElementById('meterScore');
  const meterFill = document.getElementById('meterFill');

  const payloadText = document.getElementById('payloadText');
  const copyBtn = document.getElementById('copyBtn');
  const openLinkBtn = document.getElementById('openLinkBtn');

  const metricSsl = document.getElementById('metricSsl');
  const metricShortener = document.getElementById('metricShortener');
  const metricDomain = document.getElementById('metricDomain');
  const metricPayload = document.getElementById('metricPayload');

  const aiCard = document.getElementById('aiCard');
  const aiBody = document.getElementById('aiBody');

  const historyList = document.getElementById('historyList');
  const historyCount = document.getElementById('historyCount');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  const presetButtons = document.querySelectorAll('.preset-btn');

  // Hidden canvas for QR image decoding
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  // Scan History Array from localStorage
  let scanHistory = JSON.parse(localStorage.getItem('qr_shield_history') || '[]');

  // Initialize UI
  renderHistory();

  // --- Event Listeners ---

  // Browse File Button Click
  browseBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  // File Input Change
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) handleImageFile(file);
  });

  // Drag & Drop Events
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      handleImageFile(files[0]);
    }
  });

  // Clipboard Paste Support
  document.addEventListener('paste', (e) => {
    const items = (e.clipboardData || e.originalEvent.clipboardData).items;
    for (const item of items) {
      if (item.kind === 'file' && item.type.startsWith('image/')) {
        const file = item.getAsFile();
        if (file) handleImageFile(file);
        break;
      }
    }
  });

  // Change / Reset Image
  changeImgBtn.addEventListener('click', resetScannerUI);

  // Preset Buttons Click
  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const presetType = btn.getAttribute('data-preset');
      loadPresetQR(presetType);
    });
  });

  // Copy Payload Button
  copyBtn.addEventListener('click', () => {
    const text = payloadText.textContent;
    if (text) {
      navigator.clipboard.writeText(text).then(() => {
        const originalHTML = copyBtn.innerHTML;
        copyBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12"/>
          </svg> Copied!
        `;
        setTimeout(() => copyBtn.innerHTML = originalHTML, 2000);
      });
    }
  });

  // Clear History Button
  clearHistoryBtn.addEventListener('click', () => {
    if (scanHistory.length === 0) return;
    if (confirm('Are you sure you want to clear your QR scan history?')) {
      scanHistory = [];
      localStorage.removeItem('qr_shield_history');
      renderHistory();
    }
  });

  // --- Core Processing Functions ---

  /**
   * Handle uploaded Image file
   * @param {File} file 
   */
  function handleImageFile(file) {
    if (!file.type.startsWith('image/')) {
      showError('Selected file is not an image. Please upload a PNG, JPG, or WEBP image.');
      return;
    }

    hideError();
    const reader = new FileReader();
    reader.onload = (e) => {
      const imgDataUrl = e.target.result;
      processQRImageSrc(imgDataUrl);
    };
    reader.readAsDataURL(file);
  }

  /**
   * Process QR image source URL, show scanner radar animation, decode QR
   * @param {string} imgSrc 
   * @param {string} [knownPayload] Optional pre-known payload for synthesized presets
   */
  function processQRImageSrc(imgSrc, knownPayload = null) {
    // Show image preview and radar overlay
    dropZoneContent.classList.add('hidden');
    previewContainer.classList.remove('hidden');
    qrPreview.src = imgSrc;
    radarOverlay.classList.remove('hidden');
    hideError();

    // Simulate AI Radar Scan delay for realistic UX
    setTimeout(() => {
      radarOverlay.classList.add('hidden');
      
      const img = new Image();
      img.crossOrigin = 'Anonymous';
      img.onload = () => {
        let decodedText = knownPayload;
        
        if (!decodedText) {
          decodedText = decodeQRCodeFromImage(img);
        }

        if (decodedText) {
          const analysis = analyzeSecurityRisk(decodedText);
          displayResults(decodedText, analysis);
          saveToHistory(decodedText, analysis);
        } else {
          showError('No QR code could be detected in this image. Please ensure the image is clear and well-lit.');
        }
      };
      img.onerror = () => {
        if (knownPayload) {
          const analysis = analyzeSecurityRisk(knownPayload);
          displayResults(knownPayload, analysis);
          saveToHistory(knownPayload, analysis);
        } else {
          showError('Failed to load image for scanning.');
        }
      };
      img.src = imgSrc;
    }, 900);
  }

  /**
   * Decode QR Code from HTMLImageElement using jsQR
   * @param {HTMLImageElement} img 
   * @returns {string|null}
   */
  function decodeQRCodeFromImage(img) {
    canvas.width = img.naturalWidth || img.width;
    canvas.height = img.naturalHeight || img.height;
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    
    // Attempt standard jsQR decoding
    if (window.jsQR) {
      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
      });
      if (code && code.data) return code.data;

      // Secondary attempt with inverted colors
      const codeInverted = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "onlyInvert",
      });
      if (codeInverted && codeInverted.data) return codeInverted.data;
    }
    return null;
  }

  /**
   * Risk Assessment Engine
   * Analyzes decoded text payload for quishing / phishing indicators
   * @param {string} rawContent 
   * @returns {Object} Risk analysis results
   */
  function analyzeSecurityRisk(rawContent) {
    const text = rawContent.trim();
    let isUrl = false;
    let urlObj = null;

    try {
      const parsed = new URL(text);
      const scheme = parsed.protocol.toLowerCase();
      // Only treat standard web protocols or browser schemes as URLs
      if (['http:', 'https:', 'javascript:', 'data:', 'file:'].includes(scheme)) {
        urlObj = parsed;
        isUrl = true;
      } else if (scheme === 'wifi:') {
        isUrl = false; // Wi-Fi setup string
      } else if (['mailto:', 'tel:', 'sms:', 'smsto:'].includes(scheme)) {
        isUrl = false; // Action string
      }
    } catch {
      if (text.startsWith('www.') || text.startsWith('http://') || text.startsWith('https://')) {
        try {
          urlObj = new URL('https://' + text.replace(/^(https?:\/\/)/, ''));
          isUrl = true;
        } catch {
          isUrl = false;
        }
      }
    }

    const vectors = [];
    let riskScore = 0; // 0 to 100

    // Shortener domain lookup table
    const shortenerDomains = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
      'ow.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'cutt.ly',
      'qr.ae', 'rb.gy', 'v.gd', 't.ly', 'clck.ru', 's.id', 'short.gy'
    ];

    // Suspicious high-risk TLDs
    const suspiciousTlds = [
      '.xyz', '.top', '.buzz', '.club', '.work', '.kim', '.info',
      '.online', '.zip', '.mov', '.fit', '.rest', '.gq', '.cf', '.ml',
      '.tk', '.ga', '.icu', '.cam', '.cfd'
    ];

    // Known phishing key terms in URL paths
    const phishingKeywords = [
      'login', 'verify', 'account', 'secure', 'update', 'banking',
      'auth', 'credential', 'signin', 'password', 'confirm', 'wallet'
    ];

    let sslStatus = 'Not Applicable';
    let shortenerStatus = 'Direct Link';
    let domainIntegrity = 'Standard';
    let contentType = isUrl ? 'Web URL' : 'Plain Text';

    if (isUrl && urlObj) {
      const hostname = urlObj.hostname.toLowerCase();
      const protocol = urlObj.protocol.toLowerCase();
      const pathname = urlObj.pathname.toLowerCase();
      const href = urlObj.href.toLowerCase();

      // Rule 1: HTTP Protocol (Insecure) -> DANGEROUS
      if (protocol === 'http:') {
        riskScore += 65;
        sslStatus = 'HTTP (Insecure)';
        vectors.push({
          type: 'danger',
          title: 'Unencrypted Protocol (HTTP)',
          desc: 'The link uses insecure HTTP instead of encrypted HTTPS. Data transmitted can be intercepted or manipulated.'
        });
      } else if (protocol === 'https:') {
        sslStatus = 'HTTPS (Encrypted)';
      } else if (['javascript:', 'data:', 'file:'].includes(protocol)) {
        riskScore += 90;
        sslStatus = 'Malicious Scheme';
        vectors.push({
          type: 'danger',
          title: 'Executable / Data Scheme',
          desc: 'Payload attempts to execute script code or local files directly in browser.'
        });
      }

      // Rule 2: Link Shortener Detection -> SUSPICIOUS
      const isShortener = shortenerDomains.some(d => hostname.includes(d));
      if (isShortener) {
        riskScore += 45;
        shortenerStatus = 'Shortened URL Detected';
        vectors.push({
          type: 'warning',
          title: 'URL Shortener Service Used',
          desc: `Uses shortener service (${hostname}) to obscure the final destination URL.`
        });
      }

      // Rule 3: IP Address Hostname -> DANGEROUS
      const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^0x[0-9a-f]+/i.test(hostname);
      if (isIpHost) {
        riskScore += 75;
        domainIntegrity = 'IP Address Host';
        vectors.push({
          type: 'danger',
          title: 'Raw IP Address Host',
          desc: 'Points directly to a raw IP address instead of a registered domain name, a common phishing tactic.'
        });
      }

      // Rule 4: Embedded User Credentials (@ symbol in authority) -> DANGEROUS
      if (urlObj.username || urlObj.password || urlObj.href.includes('@')) {
        riskScore += 80;
        domainIntegrity = 'Spoofed Host Authority';
        vectors.push({
          type: 'danger',
          title: 'Embedded Credentials / Authority Spoofing',
          desc: 'URL contains "@" symbol or user credentials, attempting to impersonate a legitimate domain.'
        });
      }

      // Rule 5: Suspicious TLD check
      const matchesSuspiciousTld = suspiciousTlds.some(tld => hostname.endsWith(tld));
      if (matchesSuspiciousTld) {
        riskScore += 30;
        domainIntegrity = 'Low Reputation TLD';
        vectors.push({
          type: 'warning',
          title: 'Suspicious Domain Extension (TLD)',
          desc: 'Uses a top-level domain commonly associated with low-cost spam and disposable phishing campaigns.'
        });
      }

      // Rule 6: High Randomness / Long Query Strings / Phishing Keywords
      const hasPhishingKeywords = phishingKeywords.some(kw => pathname.includes(kw) || urlObj.search.includes(kw));
      const hasExcessiveNumbers = (href.match(/\d/g) || []).length > 15;
      const longRandomPath = pathname.length > 40 || urlObj.search.length > 50;

      if (hasPhishingKeywords && (protocol === 'http:' || isShortener || matchesSuspiciousTld)) {
        riskScore += 35;
        vectors.push({
          type: 'danger',
          title: 'Phishing Keyword Patterns',
          desc: 'URL path contains authentication keywords (e.g. login, verify) paired with insecure or shortened domain.'
        });
      }

      if (hasExcessiveNumbers || longRandomPath) {
        riskScore += 25;
        vectors.push({
          type: 'warning',
          title: 'High-Entropy Query Parameters',
          desc: 'Contains long, randomized alphanumeric tokens or high digit counts often used for trackable scam links.'
        });
      }

    } else {
      // Non-URL Plain Text / Utility Payload Analysis
      if (text.toUpperCase().startsWith('WIFI:')) {
        contentType = 'Wi-Fi Network Config';
        domainIntegrity = 'Local Device Setting';
        vectors.push({
          type: 'safe',
          title: 'Wi-Fi Connection Profile',
          desc: 'Payload contains network SSID and encryption parameters for automated Wi-Fi connection.'
        });
      } else if (text.toUpperCase().startsWith('BEGIN:VCARD')) {
        contentType = 'vCard Contact Info';
        domainIntegrity = 'Contact Profile';
        vectors.push({
          type: 'safe',
          title: 'Digital Business Card (vCard)',
          desc: 'Payload contains contact details formatted for phone address book import.'
        });
      } else if (text.includes('<script>') || text.includes('cmd.exe') || text.includes('powershell')) {
        contentType = 'Raw Script Payload';
        riskScore += 85;
        vectors.push({
          type: 'danger',
          title: 'Potential Executable Code',
          desc: 'Text contains script tags or command lines that could execute if pasted into terminal.'
        });
      } else {
        contentType = 'Plain Text Payload';
        vectors.push({
          type: 'safe',
          title: 'Standard Plain Text Payload',
          desc: 'Content does not contain executable Web URLs or direct link vectors.'
        });
      }
    }

    // Cap Risk Score between 0 and 100
    riskScore = Math.min(100, Math.max(0, riskScore));

    // Determine Risk Level Categorization
    let riskLevel = 'Safe';
    if (riskScore >= 60) {
      riskLevel = 'Dangerous';
    } else if (riskScore >= 25) {
      riskLevel = 'Suspicious';
    } else {
      riskLevel = 'Safe';
    }

    return {
      riskLevel,
      riskScore,
      isUrl,
      urlObj,
      vectors,
      sslStatus,
      shortenerStatus,
      domainIntegrity,
      contentType
    };
  }

  /**
   * Display Scan Results & AI Analysis in UI
   * @param {string} content 
   * @param {Object} analysis 
   */
  function displayResults(content, analysis) {
    emptyState.classList.add('hidden');
    resultContent.classList.remove('hidden');

    // Update Risk Badge
    riskBadge.className = `risk-badge badge-${analysis.riskLevel.toLowerCase()}`;
    riskText.textContent = analysis.riskLevel;

    if (analysis.riskLevel === 'Safe') {
      riskIcon.textContent = '🛡️';
    } else if (analysis.riskLevel === 'Suspicious') {
      riskIcon.textContent = '⚠️';
    } else {
      riskIcon.textContent = '🚨';
    }

    // Update Meter
    meterScore.textContent = `${analysis.riskScore}%`;
    meterFill.className = `meter-fill fill-${analysis.riskLevel.toLowerCase()}`;
    // Delay width change for smooth CSS transition
    setTimeout(() => {
      meterFill.style.width = `${analysis.riskScore}%`;
    }, 50);

    // Update Payload Text & Buttons
    payloadText.textContent = content;

    if (analysis.isUrl) {
      openLinkBtn.classList.remove('hidden');
      openLinkBtn.href = content;
      // Add safety warning if link is suspicious or dangerous
      if (analysis.riskLevel !== 'Safe') {
        openLinkBtn.onclick = (e) => {
          if (!confirm(`⚠️ WARNING: QR Shield has flagged this link as ${analysis.riskLevel.toUpperCase()} (Risk Score: ${analysis.riskScore}%).\n\nAre you sure you want to open it in your browser?`)) {
            e.preventDefault();
          }
        };
      } else {
        openLinkBtn.onclick = null;
      }
    } else {
      openLinkBtn.classList.add('hidden');
    }

    // Update Metrics Grid
    metricSsl.querySelector('.metric-value').textContent = analysis.sslStatus;
    metricShortener.querySelector('.metric-value').textContent = analysis.shortenerStatus;
    metricDomain.querySelector('.metric-value').textContent = analysis.domainIntegrity;
    metricPayload.querySelector('.metric-value').textContent = analysis.contentType;

    // Render AI Analysis Breakdown
    renderAIAnalysis(content, analysis);
  }

  /**
   * Render Synthesized AI Reasoning Block
   * @param {string} content 
   * @param {Object} analysis 
   */
  function renderAIAnalysis(content, analysis) {
    const { riskLevel, riskScore, isUrl, vectors } = analysis;

    let summaryText = '';
    let recClass = `rec-${riskLevel.toLowerCase()}`;
    let recText = '';

    if (riskLevel === 'Safe') {
      summaryText = `AI Security Evaluation complete. The scanned QR code resolved to a clean, encrypted HTTPS endpoint. No link shorteners, spoofed IP addresses, or malicious redirection vectors were detected.`;
      recText = `✅ Safe to Proceed: This QR code appears authentic and secure for general browsing.`;
    } else if (riskLevel === 'Suspicious') {
      summaryText = `AI Security Evaluation flagged potential quishing anomalies. The payload exhibits structural obfuscation (such as URL shortener masks or non-standard TLD extensions) commonly used to bypass security filters.`;
      recText = `⚠️ Exercise Caution: Do not enter sensitive credentials (passwords, payment cards) on the target page without verifying the full destination URL.`;
    } else {
      summaryText = `🚨 Critical Risk Alert: High confidence quishing attack detected! The scanned QR code contains dangerous indicators including unencrypted HTTP protocols, IP address hosting, or authority spoofing.`;
      recText = `🛑 Do Not Open: We strongly advise against opening this link or interacting with its contents.`;
    }

    const vectorsHTML = vectors.map(v => {
      let icon = v.type === 'danger' ? '🔴' : v.type === 'warning' ? '🟡' : '🟢';
      return `
        <li class="ai-point-item">
          <span class="ai-point-icon">${icon}</span>
          <div>
            <strong>${v.title}:</strong> ${v.desc}
          </div>
        </li>
      `;
    }).join('');

    aiBody.innerHTML = `
      <div class="ai-analysis-block">
        <p class="ai-summary-text">${summaryText}</p>
        <ul class="ai-points-list">
          ${vectorsHTML}
        </ul>
        <div class="ai-recommendation ${recClass}">
          ${recText}
        </div>
      </div>
    `;
  }

  // --- Scan History Management ---

  /**
   * Save a completed scan to localStorage
   */
  function saveToHistory(content, analysis) {
    const historyItem = {
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      date: new Date().toLocaleDateString(),
      content: content.length > 50 ? content.substring(0, 47) + '...' : content,
      fullContent: content,
      riskLevel: analysis.riskLevel,
      riskScore: analysis.riskScore,
      isUrl: analysis.isUrl
    };

    // Add to top of list, limit to 15 items
    scanHistory.unshift(historyItem);
    if (scanHistory.length > 15) scanHistory.pop();

    localStorage.setItem('qr_shield_history', JSON.stringify(scanHistory));
    renderHistory();
  }

  /**
   * Render history items list
   */
  function renderHistory() {
    historyCount.textContent = `${scanHistory.length} ${scanHistory.length === 1 ? 'scan' : 'scans'}`;

    if (scanHistory.length === 0) {
      historyList.innerHTML = `<div class="no-history">No recent scans recorded. Scans will be automatically saved locally.</div>`;
      return;
    }

    historyList.innerHTML = scanHistory.map(item => `
      <div class="history-item" data-id="${item.id}">
        <div class="history-top">
          <span class="history-time">${item.date} at ${item.timestamp}</span>
          <span class="history-pill pill-${item.riskLevel.toLowerCase()}">${item.riskLevel} (${item.riskScore}%)</span>
        </div>
        <div class="history-url">${escapeHtml(item.content)}</div>
      </div>
    `).join('');

    // Re-inspect clicked history item
    document.querySelectorAll('.history-item').forEach(el => {
      el.addEventListener('click', () => {
        const itemId = parseInt(el.getAttribute('data-id'));
        const found = scanHistory.find(i => i.id === itemId);
        if (found) {
          const analysis = analyzeSecurityRisk(found.fullContent);
          displayResults(found.fullContent, analysis);
          window.scrollTo({ top: resultCard.offsetTop - 40, behavior: 'smooth' });
        }
      });
    });
  }

  // --- Quick Presets & Test Samples ---

  /**
   * Load synthetic test QR presets
   * @param {string} type 
   */
  function loadPresetQR(type) {
    let textPayload = '';
    let svgBgColor = '#1e1b4b';

    switch (type) {
      case 'safe':
        textPayload = 'https://github.com/security/qr-shield-verify';
        svgBgColor = '#064e3b';
        break;
      case 'suspicious':
        textPayload = 'https://bit.ly/3x89a_update_account_verify';
        svgBgColor = '#78350f';
        break;
      case 'dangerous':
        textPayload = 'http://192.168.1.105/login-bank-verification/auth.php?id=94032';
        svgBgColor = '#7f1d1d';
        break;
      case 'text':
        textPayload = 'WIFI:S:OfficeGuestNetwork;T:WPA;P:SecureP@ssw0rd2026;;';
        svgBgColor = '#1e3a8a';
        break;
    }

    // Generate an inline SVG QR code canvas URL for visual demonstration
    const svgDataUrl = generateDummyQRSvgDataUrl(textPayload, svgBgColor);
    processQRImageSrc(svgDataUrl, textPayload);
  }

  /**
   * Generates a high-quality SVG QR Code representation Data URL for preset testing
   */
  function generateDummyQRSvgDataUrl(payload, bgColor) {
    const svg = `
      <svg xmlns="http://www.w3.org/2000/svg" width="300" height="300" viewBox="0 0 300 300">
        <rect width="300" height="300" fill="${bgColor}" rx="16"/>
        <g fill="#ffffff">
          <!-- Position Detection Patterns (Top-Left, Top-Right, Bottom-Left) -->
          <rect x="25" y="25" width="70" height="70" rx="8" fill="#ffffff"/>
          <rect x="35" y="35" width="50" height="50" rx="4" fill="${bgColor}"/>
          <rect x="45" y="45" width="30" height="30" rx="2" fill="#ffffff"/>

          <rect x="205" y="25" width="70" height="70" rx="8" fill="#ffffff"/>
          <rect x="215" y="35" width="50" height="50" rx="4" fill="${bgColor}"/>
          <rect x="225" y="45" width="30" height="30" rx="2" fill="#ffffff"/>

          <rect x="25" y="205" width="70" height="70" rx="8" fill="#ffffff"/>
          <rect x="35" y="215" width="50" height="50" rx="4" fill="${bgColor}"/>
          <rect x="45" y="225" width="30" height="30" rx="2" fill="#ffffff"/>

          <!-- Matrix Modules -->
          <rect x="110" y="30" width="12" height="12"/>
          <rect x="130" y="30" width="12" height="12"/>
          <rect x="160" y="30" width="12" height="12"/>
          <rect x="110" y="50" width="12" height="12"/>
          <rect x="140" y="50" width="12" height="12"/>
          <rect x="170" y="50" width="12" height="12"/>

          <rect x="30" y="110" width="12" height="12"/>
          <rect x="50" y="110" width="12" height="12"/>
          <rect x="70" y="110" width="12" height="12"/>
          <rect x="110" y="110" width="12" height="12"/>
          <rect x="130" y="110" width="12" height="12"/>
          <rect x="150" y="110" width="12" height="12"/>
          <rect x="170" y="110" width="12" height="12"/>
          <rect x="210" y="110" width="12" height="12"/>
          <rect x="230" y="110" width="12" height="12"/>
          <rect x="250" y="110" width="12" height="12"/>

          <rect x="40" y="130" width="12" height="12"/>
          <rect x="60" y="130" width="12" height="12"/>
          <rect x="100" y="130" width="12" height="12"/>
          <rect x="140" y="130" width="12" height="12"/>
          <rect x="180" y="130" width="12" height="12"/>
          <rect x="220" y="130" width="12" height="12"/>
          <rect x="240" y="130" width="12" height="12"/>

          <rect x="30" y="160" width="12" height="12"/>
          <rect x="70" y="160" width="12" height="12"/>
          <rect x="110" y="160" width="12" height="12"/>
          <rect x="130" y="160" width="12" height="12"/>
          <rect x="150" y="160" width="12" height="12"/>
          <rect x="190" y="160" width="12" height="12"/>
          <rect x="230" y="160" width="12" height="12"/>

          <rect x="110" y="210" width="12" height="12"/>
          <rect x="140" y="210" width="12" height="12"/>
          <rect x="170" y="210" width="12" height="12"/>
          <rect x="210" y="210" width="12" height="12"/>
          <rect x="250" y="210" width="12" height="12"/>

          <rect x="120" y="240" width="12" height="12"/>
          <rect x="150" y="240" width="12" height="12"/>
          <rect x="180" y="240" width="12" height="12"/>
          <rect x="220" y="240" width="12" height="12"/>
          <rect x="240" y="240" width="12" height="12"/>
        </g>
      </svg>
    `;
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  }

  // --- Helper Utilities ---

  function resetScannerUI() {
    dropZoneContent.classList.remove('hidden');
    previewContainer.classList.add('hidden');
    qrPreview.src = '';
    fileInput.value = '';
    hideError();
  }

  function showError(msg) {
    errorMessage.textContent = msg;
    errorBanner.classList.remove('hidden');
  }

  function hideError() {
    errorBanner.classList.add('hidden');
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
  }
});
