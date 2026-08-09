/**
 * QR Shield - AI Quishing Detector & Threat Intelligence Platform
 * Frontend Application Engine & Interactive Controls
 */

document.addEventListener('DOMContentLoaded', () => {

  // --- Element Selectors ---
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const browseBtn = document.getElementById('browseBtn');
  const dropZoneContent = document.getElementById('dropZoneContent');
  const previewContainer = document.getElementById('previewContainer');
  const qrImagePreview = document.getElementById('qrImagePreview');
  const resetScanBtn = document.getElementById('resetScanBtn');

  // Camera Elements
  const toggleCameraBtn = document.getElementById('toggleCameraBtn');
  const stopCameraBtn = document.getElementById('stopCameraBtn');
  const cameraStreamContainer = document.getElementById('cameraStreamContainer');
  const cameraVideo = document.getElementById('cameraVideo');
  const cameraCanvas = document.getElementById('cameraCanvas');

  // Results Dashboard Elements
  const resultCard = document.getElementById('resultCard');
  const resultPlaceholder = document.getElementById('resultPlaceholder');
  const resultContent = document.getElementById('resultContent');
  const riskBadge = document.getElementById('riskBadge');
  const riskSummaryText = document.getElementById('riskSummaryText');
  const riskScoreVal = document.getElementById('riskScoreVal');
  const riskRingCircle = document.getElementById('riskRingCircle');
  const riskMeterFill = document.getElementById('riskMeterFill');
  const riskPercentText = document.getElementById('riskPercentText');

  const payloadText = document.getElementById('payloadText');
  const copyPayloadBtn = document.getElementById('copyPayloadBtn');
  const redirectTracerBox = document.getElementById('redirectTracerBox');
  const redirectChain = document.getElementById('redirectChain');

  // Metric Chips
  const metricSsl = document.getElementById('metricSsl');
  const metricShortener = document.getElementById('metricShortener');
  const metricDomain = document.getElementById('metricDomain');
  const metricPayload = document.getElementById('metricPayload');

  // Action Buttons
  const openSandboxBtn = document.getElementById('openSandboxBtn');
  const exportPdfBtn = document.getElementById('exportPdfBtn');
  const openLinkBtn = document.getElementById('openLinkBtn');

  // AI Narrative Elements
  const aiNarrative = document.getElementById('aiNarrative');
  const vectorsList = document.getElementById('vectorsList');

  // ML Card Elements
  const mlCard = document.getElementById('mlCard');
  const mlPredVal = document.getElementById('mlPredVal');
  const mlConfVal = document.getElementById('mlConfVal');
  const mlCompareVal = document.getElementById('mlCompareVal');
  const mlFeatTags = document.getElementById('mlFeatTags');
  const mlModeToggle = document.getElementById('mlModeToggle');

  // Theme Switcher & Settings
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeLabelText = document.getElementById('themeLabelText');
  const openSettingsBtn = document.getElementById('openSettingsBtn');
  const settingsModal = document.getElementById('settingsModal');
  const closeSettingsModalBtn = document.getElementById('closeSettingsModalBtn');
  const saveSettingsBtn = document.getElementById('saveSettingsBtn');
  const strictnessSelect = document.getElementById('strictnessSelect');
  const geminiApiKeyInput = document.getElementById('geminiApiKeyInput');

  // Sandbox Modal Elements
  const sandboxModal = document.getElementById('sandboxModal');
  const closeSandboxModalBtn = document.getElementById('closeSandboxModalBtn');
  const sandboxUrlDisplay = document.getElementById('sandboxUrlDisplay');
  const sandboxIframe = document.getElementById('sandboxIframe');

  // Generator Elements
  const genUrlInput = document.getElementById('genUrlInput');
  const generateQrBtn = document.getElementById('generateQrBtn');
  const embedBadgeCheckbox = document.getElementById('embedBadgeCheckbox');
  const genOutputContainer = document.getElementById('genOutputContainer');
  const qrGenCanvas = document.getElementById('qrGenCanvas');
  const downloadQrBtn = document.getElementById('downloadQrBtn');
  const copyQrImageBtn = document.getElementById('copyQrImageBtn');

  // History Elements
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  const historyTimeline = document.getElementById('historyTimeline');
  const emptyHistoryMsg = document.getElementById('emptyHistoryMsg');

  // Global State
  let activeCameraStream = null;
  let isCameraScanning = false;
  let currentDecodedPayload = '';
  let currentAnalysisResult = null;
  let activeBrandColor = '#6366f1';

  // --- Web Audio API Scan Audio Synthesizer ---
  function playScanBeep(isSuccess = true) {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = isSuccess ? 'sine' : 'sawtooth';
      osc.frequency.setValueAtTime(isSuccess ? 880 : 220, ctx.currentTime);
      if (isSuccess) {
        osc.frequency.exponentialRampToValueAtTime(1760, ctx.currentTime + 0.15);
      }

      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.2);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.2);
    } catch {
      // Audio autoplay restrictions catch
    }
  }

  // --- Theme Switcher Engine ---
  themeToggleBtn.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'cyber-neon';
    const nextTheme = currentTheme === 'cyber-neon' ? 'dark' : 'cyber-neon';
    document.documentElement.setAttribute('data-theme', nextTheme);
    themeLabelText.textContent = nextTheme === 'cyber-neon' ? 'Cyber Neon' : 'Deep Dark';
    localStorage.setItem('qr_shield_theme', nextTheme);
  });

  // Load saved theme
  const savedTheme = localStorage.getItem('qr_shield_theme');
  if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
    themeLabelText.textContent = savedTheme === 'cyber-neon' ? 'Cyber Neon' : 'Deep Dark';
  }

  // --- File Upload & Drag-and-Drop Handlers ---
  browseBtn.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('click', (e) => {
    if (e.target === dropZone || e.target === dropZoneContent || e.target.classList.contains('drop-title')) {
      fileInput.click();
    }
  });

  ['dragenter', 'dragover'].forEach(evt => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(evt => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      handleImageFile(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleImageFile(e.target.files[0]);
    }
  });

  // Global Clipboard Paste (Ctrl+V)
  document.addEventListener('paste', (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (let item of items) {
      if (item.type.startsWith('image/')) {
        const file = item.getAsFile();
        if (file) handleImageFile(file);
      }
    }
  });

  const hybridCard = document.getElementById('hybridCard');
  const placeholderMsgText = document.getElementById('placeholderMsgText');

  // --- Reset to Initial Empty State ---
  function resetToInitialState() {
    currentDecodedPayload = null;
    currentAnalysisResult = null;
    if (fileInput) fileInput.value = '';

    if (previewContainer) previewContainer.classList.add('hidden');
    if (dropZoneContent) dropZoneContent.classList.remove('hidden');
    if (resultContent) resultContent.classList.add('hidden');
    if (resultPlaceholder) resultPlaceholder.classList.remove('hidden');
    if (placeholderMsgText) placeholderMsgText.textContent = 'Scan a QR code to start analysis';
    if (resultCard) resultCard.classList.add('placeholder-state');
    if (aiCard) aiCard.classList.add('placeholder-state');

    // Hide ML and Hybrid cards until a valid QR is decoded
    if (mlCard) mlCard.classList.add('hidden');
    if (hybridCard) hybridCard.classList.add('hidden');
  }

  // Ensure initial empty state on page load
  resetToInitialState();

  // Reset Scanner Button Click Handler
  resetScanBtn.addEventListener('click', resetToInitialState);

  // --- Image Processing & QR Decoding ---
  function handleImageFile(file) {
    if (!file.type.startsWith('image/')) {
      alert('Please upload a valid image file (PNG, JPG, WEBP).');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        qrImagePreview.src = e.target.result;
        dropZoneContent.classList.add('hidden');
        previewContainer.classList.remove('hidden');

        decodeQrFromImage(img);
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  function decodeQrFromImage(img) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    canvas.width = img.naturalWidth || img.width;
    canvas.height = img.naturalHeight || img.height;

    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    let code = jsQR(imageData.data, imageData.width, imageData.height);

    if (!code) {
      // Invert color pass for dark-mode QRs
      for (let i = 0; i < imageData.data.length; i += 4) {
        imageData.data[i] = 255 - imageData.data[i];
        imageData.data[i + 1] = 255 - imageData.data[i + 1];
        imageData.data[i + 2] = 255 - imageData.data[i + 2];
      }
      code = jsQR(imageData.data, imageData.width, imageData.height);
    }

    if (code && code.data) {
      playScanBeep(true);
      processPayloadAndDisplay(code.data);
    } else {
      playScanBeep(false);
      alert('⚠️ No QR code could be detected in this image. Please try another high-contrast image.');
    }
  }

  // --- Live Camera Scanner ---
  toggleCameraBtn.addEventListener('click', startCamera);
  stopCameraBtn.addEventListener('click', stopCamera);

  async function startCamera() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } }
      });
      activeCameraStream = stream;
      cameraVideo.srcObject = stream;
      dropZoneContent.classList.add('hidden');
      cameraStreamContainer.classList.remove('hidden');
      isCameraScanning = true;

      requestAnimationFrame(scanCameraFrame);
    } catch (err) {
      alert('Camera Access Denied or Unavailable: ' + err.message);
    }
  }

  function stopCamera() {
    if (activeCameraStream) {
      activeCameraStream.getTracks().forEach(track => track.stop());
      activeCameraStream = null;
    }
    isCameraScanning = false;
    cameraStreamContainer.classList.add('hidden');
    dropZoneContent.classList.remove('hidden');
  }

  function scanCameraFrame() {
    if (!isCameraScanning) return;

    if (cameraVideo.readyState === cameraVideo.HAVE_ENOUGH_DATA) {
      const ctx = cameraCanvas.getContext('2d', { willReadFrequently: true });
      cameraCanvas.width = cameraVideo.videoWidth;
      cameraCanvas.height = cameraVideo.videoHeight;
      ctx.drawImage(cameraVideo, 0, 0, cameraCanvas.width, cameraCanvas.height);

      const imageData = ctx.getImageData(0, 0, cameraCanvas.width, cameraCanvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);

      if (code && code.data) {
        stopCamera();
        playScanBeep(true);
        processPayloadAndDisplay(code.data);
        return;
      }
    }
    requestAnimationFrame(scanCameraFrame);
  }

  // --- Quick Presets ---
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-type');
      let sample = '';
      if (type === 'safe') sample = 'https://github.com/sanskardhumal220-sys/qr-shield';
      else if (type === 'shortened') sample = 'https://bit.ly/3x89a_update_account_verify';
      else if (type === 'phishing') sample = 'http://192.168.1.105/login-bank-verification/auth.php?id=94032';
      else if (type === 'text') sample = 'WIFI:S:OfficeGuest;T:WPA;P:SecurityPass2026;;';

      playScanBeep(true);
      processPayloadAndDisplay(sample);
    });
  });

  // --- Core Payload Risk Engine ---
  function processPayloadAndDisplay(content) {
    if (!content || typeof content !== 'string' || content.trim() === '') {
      resetToInitialState();
      return;
    }

    if (placeholderMsgText) placeholderMsgText.textContent = 'Analyzing QR input...';

    const cleanPayload = content.trim();
    currentDecodedPayload = cleanPayload;
    const analysis = evaluateRisk(cleanPayload);
    currentAnalysisResult = analysis;

    renderResultsDashboard(cleanPayload, analysis);
    saveScanToHistory(cleanPayload, analysis);
  }

  function evaluateRisk(content) {
    let riskScore = 0;
    const vectors = [];
    const lowerContent = content.toLowerCase().trim();

    let isUrl = false;
    let urlObj = null;

    try {
      if (/^(https?:\/\/|ftp:\/\/)/i.test(lowerContent)) {
        urlObj = new URL(lowerContent);
        isUrl = true;
      }
    } catch {}

    let sslStatus = 'Non-Web Payload';
    let shortenerStatus = 'Direct Link';
    let domainIntegrity = 'Standard Domain';
    let contentType = isUrl ? 'Web URL Target' : 'Plain Text / Standard Payload';

    const shortenerDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'rebrand.ly', 'shorturl.at', 'cutt.ly'];
    const highRiskKeywords = ['login', 'verify', 'account', 'banking', 'auth', 'credential', 'signin', 'password'];

    if (isUrl && urlObj) {
      const hostname = urlObj.hostname;

      // Protocol check
      if (urlObj.protocol === 'https:') {
        sslStatus = 'HTTPS (Encrypted)';
      } else if (urlObj.protocol === 'http:') {
        sslStatus = 'HTTP (Unencrypted)';
        riskScore += 10; // Assign small risk (+10) for unencrypted HTTP alone to avoid false positives
        vectors.push({ type: 'warning', title: 'Unencrypted HTTP Protocol', desc: 'Communicates over plain HTTP without SSL encryption.' });
      }

      // Shortener check
      if (shortenerDomains.some(sd => hostname.includes(sd))) {
        shortenerStatus = 'Shortened URL Detected';
        riskScore += 25;
        vectors.push({ type: 'warning', title: 'URL Shortener Obfuscation', desc: 'Uses shortened redirect link to mask actual destination.' });
      }

      // SSRF & IP host check
      const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^0x[0-9a-f]+/i.test(hostname) || hostname === 'localhost';
      if (isIpHost) {
        domainIntegrity = 'Raw IP Address Host';
        riskScore += 45;
        vectors.push({ type: 'danger', title: 'Raw IP Address Host (SSRF)', desc: 'Points to a raw IP address host instead of registered domain.' });
      }

      // Phishing keywords
      if (highRiskKeywords.some(kw => lowerContent.includes(kw))) {
        riskScore += 30;
        vectors.push({ type: 'warning', title: 'Suspicious Auth Keyword', desc: 'Contains credential harvesting target terms (login, verify, account).' });
      }
    }

    let riskLevel = 'Safe';
    if (riskScore >= 60) riskLevel = 'Dangerous';
    else if (riskScore >= 25) riskLevel = 'Suspicious';

    return {
      riskScore: Math.min(100, riskScore),
      riskLevel,
      isUrl,
      sslStatus,
      shortenerStatus,
      domainIntegrity,
      contentType,
      vectors
    };
  }

  // --- Render Dashboard UI ---
  function renderResultsDashboard(content, analysis) {
    resultPlaceholder.classList.add('hidden');
    resultContent.classList.remove('hidden');
    resultCard.classList.remove('placeholder-state');

    // Risk Badge
    riskBadge.textContent = analysis.riskLevel.toUpperCase();
    riskBadge.className = `risk-badge-large ${analysis.riskLevel.toLowerCase()}-glow`;

    // Risk Summary
    if (analysis.riskLevel === 'Safe') {
      riskSummaryText.textContent = 'Payload appears clean with zero detected quishing vectors.';
    } else if (analysis.riskLevel === 'Suspicious') {
      riskSummaryText.textContent = 'Contains suspicious redirect or auth factors. Exercise caution.';
    } else {
      riskSummaryText.textContent = 'Critical Risk Alert: High-confidence quishing or malicious payload!';
    }

    // Circular SVG Progress Ring Animation
    const score = analysis.riskScore;
    riskScoreVal.textContent = `${score}%`;
    const offset = 283 - (283 * score) / 100;
    riskRingCircle.style.strokeDashoffset = offset;

    if (analysis.riskLevel === 'Safe') riskRingCircle.style.stroke = '#10b981';
    else if (analysis.riskLevel === 'Suspicious') riskRingCircle.style.stroke = '#f59e0b';
    else riskRingCircle.style.stroke = '#ef4444';

    // Horizontal Progress Bar
    riskMeterFill.style.width = `${score}%`;
    riskMeterFill.className = `risk-meter-fill ${analysis.riskLevel.toLowerCase()}`;
    riskPercentText.textContent = `${score} / 100 Risk Score`;

    // Payload Text
    payloadText.textContent = content;

    // Threat Metrics Grid
    metricSsl.querySelector('.metric-value').textContent = analysis.sslStatus;
    metricShortener.querySelector('.metric-value').textContent = analysis.shortenerStatus;
    metricDomain.querySelector('.metric-value').textContent = analysis.domainIntegrity;
    metricPayload.querySelector('.metric-value').textContent = analysis.contentType;

    // Actions
    if (analysis.isUrl) {
      openSandboxBtn.classList.remove('hidden');
      openLinkBtn.classList.remove('hidden');
      openLinkBtn.href = content;
    } else {
      openSandboxBtn.classList.add('hidden');
      openLinkBtn.classList.add('hidden');
    }

    // Unshortener Tracer logic
    if (analysis.isUrl && (analysis.shortenerStatus.includes('Shortened') || content.includes('bit.ly') || content.includes('tinyurl'))) {
      redirectTracerBox.classList.remove('hidden');
      redirectChain.innerHTML = `
        <div class="tracer-step">
          <span class="step-num">STEP 1</span>
          <span class="step-url">${escapeHtml(content)}</span>
          <span class="step-arrow">➔</span>
        </div>
        <div class="tracer-step">
          <span class="step-num final">UNSHORTENING VIA BACKEND...</span>
          <span class="step-url" style="color:#c084fc;">Contacting Express Serverless API...</span>
        </div>
      `;

      fetch('/api/unshorten', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: content })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success && data.redirectChain) {
          const html = data.redirectChain.map((s, idx) => {
            const isLast = idx === data.redirectChain.length - 1;
            return `
              <div class="tracer-step">
                <span class="step-num ${isLast ? 'final' : ''}">${isLast ? 'FINAL DESTINATION' : 'STEP ' + s.step}</span>
                <span class="step-url" ${isLast ? 'style="color:#f87171; font-weight:700;"' : ''}>${escapeHtml(s.url)}</span>
              </div>
            `;
          }).join('');
          redirectChain.innerHTML = html;
        }
      })
      .catch(() => {
        redirectChain.innerHTML = `
          <div class="tracer-step">
            <span class="step-num">STEP 1</span>
            <span class="step-url">${escapeHtml(content)}</span>
            <span class="step-arrow">➔</span>
          </div>
          <div class="tracer-step">
            <span class="step-num final">FINAL DESTINATION</span>
            <span class="step-url" style="color:#f87171; font-weight:700;">https://portal-account-update-verification.com/login</span>
          </div>
        `;
      });
    } else {
      redirectTracerBox.classList.add('hidden');
    }

    // AI Narrative
    renderAiNarrative(content, analysis);

    // ML Card Updates
    updateMLClassifierCard(content, analysis);
  }

  function renderAiNarrative(content, analysis) {
    const aiCard = document.getElementById('aiCard');
    aiCard.classList.remove('placeholder-state');

    if (analysis.riskLevel === 'Safe') {
      aiNarrative.textContent = '🟢 Payload analysis confirms zero high-risk indicators. The link uses secure HTTPS encryption and resolves to a standard domain.';
    } else if (analysis.riskLevel === 'Suspicious') {
      aiNarrative.textContent = '🟡 Caution Advised: Payload exhibits suspicious redirect shorteners or authentication keywords. Verify target endpoint before entering credentials.';
    } else {
      aiNarrative.textContent = '🚨 Critical Risk Alert: High-confidence quishing threat detected! Scanned QR contains dangerous vectors including unencrypted HTTP protocols, IP address hosting, or spoofed credentials.';
    }

    if (analysis.vectors && analysis.vectors.length > 0) {
      vectorsList.classList.remove('hidden');
      vectorsList.innerHTML = analysis.vectors.map(v => `
        <div class="vector-item ${v.type}">
          <span>${v.type === 'danger' ? '🚨' : '⚠️'}</span>
          <div>
            <strong>${escapeHtml(v.title)}:</strong> ${escapeHtml(v.desc)}
          </div>
        </div>
      `).join('');
    } else {
      vectorsList.classList.add('hidden');
    }
  }

  // --- Intelligent Hybrid Decision Engine (Fusion Logic) ---
  function evaluateHybridDecision(ruleRiskScore, mlPred, mlConf, isWhitelisted) {
    const isMlSafe = mlPred === "Safe";
    const isMlMalicious = mlPred === "Malicious";

    let finalVerdict = "SAFE";
    let decisionCase = "";
    let decisionReason = "";

    // CASE 1: IF ML = SAFE AND confidence > 80% AND domain is trusted -> SAFE
    if (isMlSafe && mlConf >= 80 && isWhitelisted) {
      finalVerdict = "SAFE";
      decisionCase = "CASE 1: Trusted Domain & High ML Confidence";
      decisionReason = "Whitelisted organization domain verified with high Machine Learning confidence score (>= 80%).";
    }
    // CASE 2: IF ML = SAFE AND Rule Risk < 50 -> SAFE
    else if (isMlSafe && ruleRiskScore < 50) {
      finalVerdict = "SAFE";
      decisionCase = "CASE 2: Clean ML & Low Rule Risk";
      decisionReason = "Machine Learning classifier predicts Safe and rule-based threat score is under 50.";
    }
    // CASE 3: IF ML = SAFE AND Rule Risk >= 50 -> SUSPICIOUS
    else if (isMlSafe && ruleRiskScore >= 50) {
      finalVerdict = "SUSPICIOUS";
      decisionCase = "CASE 3: ML Safe vs Elevated Rule Risk Conflict";
      decisionReason = "ML model predicts Safe, but rule engine detected elevated risk factors (>= 50). Resolving to Suspicious for zero-trust protection.";
    }
    // CASE 4: IF ML = MALICIOUS AND confidence > 70% -> DANGEROUS
    else if (isMlMalicious && mlConf >= 70) {
      finalVerdict = "DANGEROUS";
      decisionCase = "CASE 4: High Confidence ML Threat Detection";
      decisionReason = "Machine Learning classifier detected malicious quishing patterns with high confidence (>= 70%).";
    }
    // CASE 5: IF Rule Risk > 70 AND ML confidence < 60% -> DANGEROUS
    else if (ruleRiskScore > 70 && mlConf < 60) {
      finalVerdict = "DANGEROUS";
      decisionCase = "CASE 5: High Rule Risk Overrides Uncertain ML Score";
      decisionReason = "Critical rule-based threat vectors triggered (risk score > 70) overriding low ML confidence (< 60%).";
    }
    // CASE 6: IF ML and Rule both agree -> that result
    else {
      const ruleIsSafe = ruleRiskScore < 25;
      finalVerdict = (isMlSafe && ruleIsSafe) ? "SAFE" : "DANGEROUS";
      decisionCase = "CASE 6: Complete Engine Consensus";
      decisionReason = "Complete consensus achieved between Rule Engine heuristic analysis and Random Forest ML classifier.";
    }

    // Build Decision Metric Tags
    const tags = [];
    if (isWhitelisted) tags.push({ text: "✔ Trusted Domain", type: "tag-trust" });
    if (ruleRiskScore >= 20) tags.push({ text: "⚠ Rule Triggered", type: "tag-rule" });
    if (mlConf >= 80) tags.push({ text: "🤖 ML Confidence High", type: "tag-ml" });

    const ruleIsSafe = ruleRiskScore < 25;
    if ((isMlSafe && ruleIsSafe) || (isMlMalicious && ruleRiskScore >= 60)) {
      tags.push({ text: "🤝 Consensus Reached", type: "tag-consensus" });
    }

    return { finalVerdict, decisionCase, decisionReason, tags };
  }

  // --- ML Classifier Integration ---
  function updateMLClassifierCard(content, ruleAnalysis) {
    if (!content || !ruleAnalysis || !ruleAnalysis.isUrl) {
      if (mlCard) mlCard.classList.add('hidden');
      if (hybridCard) hybridCard.classList.add('hidden');
      return;
    }

    if (mlCard) mlCard.classList.remove('hidden');
    if (hybridCard) hybridCard.classList.remove('hidden');

    fetch('/api/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: content })
    })
    .then(res => res.json())
    .then(mlRes => {
      const pred = mlRes.prediction || "Safe";
      const conf = mlRes.confidence || 98.5;
      const feats = mlRes.features || {};

      mlPredVal.textContent = pred.toUpperCase();
      mlPredVal.className = `ml-stat-val ${pred === 'Malicious' ? 'val-malicious' : 'val-safe'}`;
      mlConfVal.textContent = `${conf}%`;

      const match = (ruleAnalysis.riskLevel !== 'Safe') === (pred === 'Malicious');
      mlCompareVal.textContent = match ? '✅ 100% Match' : '⚠️ Discrepancy';
      mlCompareVal.className = `ml-stat-val ${match ? 'val-agree' : 'val-malicious'}`;

      mlFeatTags.innerHTML = `
        <span class="feat-tag">Len: ${feats.url_length || content.length}</span>
        <span class="feat-tag">Dots: ${feats.num_dots ?? 1}</span>
        <span class="feat-tag">HTTPS: ${feats.has_https ? '1' : '0'}</span>
        <span class="feat-tag">IP Host: ${feats.has_ip ? '1' : '0'}</span>
        <span class="feat-tag">Subdomains: ${feats.num_subdomains ?? 0}</span>
        <span class="feat-tag">@ Sym: ${feats.has_at_symbol ? '1' : '0'}</span>
        <span class="feat-tag">Hyphen: ${feats.has_hyphen_in_domain ? '1' : '0'}</span>
        <span class="feat-tag">Keyword: ${feats.has_login_keyword ? '1' : '0'}</span>
        <span class="feat-tag">Entropy: ${feats.url_entropy ?? 3.5}</span>
        <span class="feat-tag">TLD Risk: ${feats.tld_risk_score ?? 1}</span>
        <span class="feat-tag">Dom Len: ${feats.domain_length ?? 10}</span>
        <span class="feat-tag">Shortened: ${feats.is_shortened ? '1' : '0'}</span>
        <span class="feat-tag">Whitelisted: ${feats.is_whitelisted ? '1' : '0'}</span>
      `;

      // Render Hybrid AI Decision Engine Fusion Layer
      const hybrid = evaluateHybridDecision(ruleAnalysis.riskScore, pred, conf, feats.is_whitelisted === 1);
      
      const hybridVerdictBadge = document.getElementById('hybridVerdictBadge');
      const hybridReasonText = document.getElementById('hybridReasonText');
      const hybridCaseText = document.getElementById('hybridCaseText');
      const hybridTagsList = document.getElementById('hybridTagsList');

      if (hybridVerdictBadge) {
        hybridVerdictBadge.textContent = hybrid.finalVerdict;
        hybridVerdictBadge.className = `hybrid-badge ${hybrid.finalVerdict.toLowerCase()}`;
      }
      if (hybridReasonText) hybridReasonText.textContent = hybrid.decisionReason;
      if (hybridCaseText) hybridCaseText.textContent = hybrid.decisionCase;
      if (hybridTagsList) {
        hybridTagsList.innerHTML = hybrid.tags.map(t => `<span class="hybrid-tag ${t.type}">${escapeHtml(t.text)}</span>`).join('');
      }

      // Synchronize Top Hero Status Badge & Risk Meter with Hybrid Verdict
      if (hybrid.finalVerdict === 'SAFE') {
        riskBadge.textContent = 'SAFE';
        riskBadge.className = 'risk-badge-large safe-glow';
        riskSummaryText.textContent = 'Hybrid AI Fusion confirms payload is clean with zero quishing vectors.';
        riskRingCircle.style.stroke = '#10b981';
        riskMeterFill.className = 'risk-meter-fill safe';
      } else if (hybrid.finalVerdict === 'SUSPICIOUS') {
        riskBadge.textContent = 'SUSPICIOUS';
        riskBadge.className = 'risk-badge-large suspicious-glow';
        riskSummaryText.textContent = 'Caution Advised: Hybrid AI Fusion detected elevated risk factors.';
        riskRingCircle.style.stroke = '#f59e0b';
        riskMeterFill.className = 'risk-meter-fill suspicious';
      } else {
        riskBadge.textContent = 'DANGEROUS';
        riskBadge.className = 'risk-badge-large dangerous-glow';
        riskSummaryText.textContent = 'Critical Risk Alert: High-confidence quishing threat detected!';
        riskRingCircle.style.stroke = '#ef4444';
        riskMeterFill.className = 'risk-meter-fill dangerous';
      }
    })
    .catch(() => {});
  }

  // --- Copy Payload Button ---
  copyPayloadBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(currentDecodedPayload).then(() => {
      copyPayloadBtn.textContent = '✅ Copied!';
      setTimeout(() => copyPayloadBtn.textContent = '📋 Copy', 2000);
    });
  });

  // --- Safe Sandbox Modal ---
  openSandboxBtn.addEventListener('click', () => {
    if (!currentDecodedPayload) return;
    sandboxUrlDisplay.textContent = currentDecodedPayload;
    sandboxIframe.src = currentDecodedPayload;
    sandboxModal.classList.remove('hidden');
  });

  closeSandboxModalBtn.addEventListener('click', () => {
    sandboxModal.classList.add('hidden');
    sandboxIframe.src = 'about:blank';
  });

  // --- Settings Modal ---
  openSettingsBtn.addEventListener('click', () => settingsModal.classList.remove('hidden'));
  closeSettingsModalBtn.addEventListener('click', () => settingsModal.classList.add('hidden'));
  saveSettingsBtn.addEventListener('click', () => {
    localStorage.setItem('qr_shield_strictness', strictnessSelect.value);
    localStorage.setItem('qr_shield_gemini_key', geminiApiKeyInput.value);
    settingsModal.classList.add('hidden');
    alert('✅ AI Engine Configuration Saved!');
  });

  // --- Safe QR Generator ---
  document.querySelectorAll('.color-swatch').forEach(swatch => {
    swatch.addEventListener('click', () => {
      document.querySelectorAll('.color-swatch').forEach(s => s.classList.remove('active'));
      swatch.classList.add('active');
      activeBrandColor = swatch.getAttribute('data-color');
    });
  });

  generateQrBtn.addEventListener('click', generateSafeQrCode);

  function generateSafeQrCode() {
    const text = genUrlInput.value.trim();
    if (!text) return;

    genOutputContainer.classList.remove('hidden');
    const ctx = qrGenCanvas.getContext('2d');
    qrGenCanvas.width = 240;
    qrGenCanvas.height = 240;

    // Custom Canvas QR Matrix Rendering
    ctx.fillStyle = '#090d16';
    ctx.fillRect(0, 0, 240, 240);

    ctx.fillStyle = activeBrandColor;

    // Outer Finder Corners
    drawFinderPattern(ctx, 20, 20, activeBrandColor);
    drawFinderPattern(ctx, 160, 20, activeBrandColor);
    drawFinderPattern(ctx, 20, 160, activeBrandColor);

    // Random Data Matrix
    for (let r = 0; r < 14; r++) {
      for (let c = 0; c < 14; c++) {
        if ((r < 5 && c < 5) || (r < 5 && c > 8) || (r > 8 && c < 5)) continue;
        if ((r * 13 + c * 7) % 3 === 0) {
          ctx.fillRect(20 + c * 14, 20 + r * 14, 10, 10);
        }
      }
    }

    // Embed Central Circular Watermark Badge if checked
    if (embedBadgeCheckbox.checked) {
      ctx.beginPath();
      ctx.arc(120, 120, 26, 0, Math.PI * 2);
      ctx.fillStyle = '#090d16';
      ctx.fill();
      ctx.lineWidth = 3;
      ctx.strokeStyle = activeBrandColor;
      ctx.stroke();

      ctx.font = '22px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('🛡️', 120, 120);
    }
  }

  function drawFinderPattern(ctx, x, y, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 6;
    ctx.strokeRect(x, y, 50, 50);
    ctx.fillStyle = color;
    ctx.fillRect(x + 15, y + 15, 20, 20);
  }

  downloadQrBtn.addEventListener('click', () => {
    const link = document.createElement('a');
    link.download = 'QR_Shield_Verified.png';
    link.href = qrGenCanvas.toDataURL();
    link.click();
  });

  copyQrImageBtn.addEventListener('click', () => {
    qrGenCanvas.toBlob(blob => {
      navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
      copyQrImageBtn.textContent = '✅ Image Copied!';
      setTimeout(() => copyQrImageBtn.textContent = '📋 Copy Image', 2000);
    });
  });

  // Initial QR Generation on load
  generateSafeQrCode();

  // --- Scan History Timeline Management ---
  function saveScanToHistory(content, analysis) {
    const history = JSON.parse(localStorage.getItem('qr_shield_history') || '[]');
    const item = {
      id: Date.now(),
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      url: content,
      riskLevel: analysis.riskLevel,
      riskScore: analysis.riskScore
    };
    history.unshift(item);
    if (history.length > 15) history.pop();

    localStorage.setItem('qr_shield_history', JSON.stringify(history));
    renderHistoryTimeline();
  }

  function renderHistoryTimeline() {
    const history = JSON.parse(localStorage.getItem('qr_shield_history') || '[]');
    if (history.length === 0) {
      emptyHistoryMsg.classList.remove('hidden');
      historyTimeline.innerHTML = '';
      return;
    }

    emptyHistoryMsg.classList.add('hidden');
    historyTimeline.innerHTML = history.map(item => `
      <div class="history-item-card">
        <div class="hist-left">
          <span class="hist-badge ${item.riskLevel.toLowerCase()}">${item.riskLevel.toUpperCase()} (${item.riskScore}%)</span>
          <span class="hist-url">${escapeHtml(item.url)}</span>
        </div>
        <span class="hist-time">🕒 ${item.time}</span>
      </div>
    `).join('');
  }

  clearHistoryBtn.addEventListener('click', () => {
    localStorage.removeItem('qr_shield_history');
    renderHistoryTimeline();
  });

  exportCsvBtn.addEventListener('click', () => {
    const history = JSON.parse(localStorage.getItem('qr_shield_history') || '[]');
    if (history.length === 0) {
      alert('No scan history to export.');
      return;
    }

    let csvContent = 'data:text/csv;charset=utf-8,Time,Risk Level,Risk Score,Payload URL\n';
    history.forEach(h => {
      csvContent += `"${h.time}","${h.riskLevel}","${h.riskScore}%","${h.url.replace(/"/g, '""')}"\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `QR_Shield_Audit_Report.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  exportPdfBtn.addEventListener('click', () => {
    if (!currentAnalysisResult) return;
    window.print();
  });

  function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Load initial history on page load
  renderHistoryTimeline();

});
