/**
 * Siyada — Mock Vision Agent
 *
 * Stands in for the Jetson Orin Nano service while the local model is being
 * built, and lets the image flow be demoed with no cloud call at all.
 *
 *   node server/tools/mock-vision.js
 *   VISION_URL=http://localhost:3999 npm start
 *
 * Responds to every image as if it were an Emirates ID card. Set
 * MOCK_CLEAN=1 to respond as if every image were clean.
 */

import { createServer } from 'node:http';

const PORT  = Number(process.env.PORT || 3999);
const CLEAN = process.env.MOCK_CLEAN === '1';

const CLEAN_RESULT = {
  hasPII: false,
  imageDescription: 'A diagram with no personal data',
  items: [],
  regulations: [],
  summary: 'No UAE-sensitive data found',
  safeToSend: true,
};

const FLAGGED_RESULT = {
  hasPII: true,
  imageDescription: 'Front of a UAE Emirates ID card',
  items: [
    {
      type: 'emirates_id',
      value: '784-1990-1234567-1',
      masked: '[EMIRATES-ID]',
      regulation: 'Federal Law 2/2019, Art. 13',
      severity: 'critical',
      box: [0.42, 0.58, 0.44, 0.09],
    },
    {
      type: 'name',
      value: 'Ahmed Al-Mansouri',
      masked: '[NAME]',
      regulation: 'UAE PDPL (Decree-Law 45/2021)',
      severity: 'medium',
      box: [0.42, 0.34, 0.40, 0.08],
    },
    {
      type: 'face',
      value: 'Cardholder photograph',
      masked: '[FACE]',
      regulation: 'UAE PDPL (Decree-Law 45/2021)',
      severity: 'high',
      box: [0.06, 0.28, 0.28, 0.52],
    },
  ],
  regulations: ['Federal Law 2/2019, Art. 13', 'UAE PDPL (Decree-Law 45/2021)'],
  summary: 'Emirates ID card — identity number, name and face are visible',
  safeToSend: false,
};

createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405).end();
    return;
  }
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    let mediaType = 'image/png';
    try { ({ mediaType = 'image/png' } = JSON.parse(body)); } catch { /* ignore */ }
    console.log(`[mock-vision] ${mediaType} ${Math.round(body.length / 1024)}KB → ${CLEAN ? 'clean' : 'flagged'}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(CLEAN ? CLEAN_RESULT : FLAGGED_RESULT));
  });
}).listen(PORT, () => {
  console.log(`Mock vision agent on http://localhost:${PORT} (${CLEAN ? 'clean' : 'flagged'} mode)`);
});
