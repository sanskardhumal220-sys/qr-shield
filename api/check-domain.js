const dns = require('dns').promises;

module.exports = async (req, res) => {
  // Add CORS headers
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
    const { domain } = req.body || {};
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
};
