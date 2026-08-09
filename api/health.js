module.exports = (req, res) => {
  res.status(200).json({
    status: 'online',
    service: 'QR Shield Backend Threat Intelligence Engine',
    timestamp: new Date().toISOString()
  });
};
