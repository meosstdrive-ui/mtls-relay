const http = require('http');
const https = require('https');
const forge = require('node-forge');

const RELAY_SECRET = process.env.MTLS_RELAY_SECRET || '';
const PORT = parseInt(process.env.PORT) || 3000;

if (!RELAY_SECRET) {
  console.error('[mTLS Relay] ERRO: MTLS_RELAY_SECRET não definido.');
  process.exit(1);
}

function parsePfx(pfxBase64, password) {
  const pfxBytes = Buffer.from(pfxBase64, 'base64');
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(pfxBytes));
  const pfx = forge.pkcs12.pkcs12FromAsn1(asn1, password);
  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
  if (!keyBag?.key) throw new Error('Chave privada não encontrada no PFX');
  const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const allCerts = certBags[forge.pki.oids.certBag] || [];
  if (!allCerts.length || !allCerts[0]?.cert) throw new Error('Certificado não encontrado no PFX');
  const certs = allCerts.map(b => b.cert).filter(Boolean);
  let leafCert = certs[0];
  let intermediates = [];
  if (certs.length > 1) {
    const subjectsThatAreIssuers = new Set(certs.map(c => c.issuer?.hash));
    leafCert = certs.find(c => !subjectsThatAreIssuers.has(c.subject?.hash)) || certs[0];
    intermediates = certs.filter(c => c !== leafCert);
  }
  const certPem = forge.pki.certificateToPem(leafCert) + intermediates.map(c => forge.pki.certificateToPem(c)).join('');
  const keyPem = forge.pki.privateKeyToPem(keyBag.key);
  return { certPem, keyPem };
}

function makeMtlsRequest(endpoint, soapBody, soapAction, certPem, keyPem, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint);
    const options = {
      hostname: url.hostname,
      port: parseInt(url.port) || 443,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': soapAction || '""',
        'Content-Length': Buffer.byteLength(soapBody),
        'User-Agent': 'MEOSST-NFSe/1.0',
        'Connection': 'close',
      },
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: true,
    };
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (c) => body += c.toString('utf8'));
      res.on('end', () => {
        if ((res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307) && redirectCount < 5 && res.headers.location) {
          const nextUrl = new URL(res.headers.location, endpoint).toString();
          makeMtlsRequest(nextUrl, soapBody, soapAction, certPem, keyPem, redirectCount + 1).then(resolve).catch(reject);
          return;
        }
        const rawHeaders = Object.entries(res.headers).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(',') : v}`).join('\n');
        resolve({ httpStatus: res.statusCode || 0, responseBody: body, rawHeaders });
      });
    });
    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(); reject(new Error('Timeout 60s no webservice municipal')); });
    req.write(soapBody);
    req.end();
  });
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed. Use POST.' }));
    return;
  }
  const secret = req.headers['x-relay-secret'] || '';
  if (!RELAY_SECRET || secret !== RELAY_SECRET) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }
  let body = '';
  req.on('data', (c) => body += c.toString('utf8'));
  req.on('end', async () => {
    try {
      const { endpoint, soap_body, soap_action, pfx_base64, pfx_password } = JSON.parse(body);
      if (!endpoint || !soap_body || !pfx_base64) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'endpoint, soap_body e pfx_base64 são obrigatórios' }));
        return;
      }
      const { certPem, keyPem } = parsePfx(pfx_base64, pfx_password || '');
      const result = await makeMtlsRequest(endpoint, soap_body, soap_action, certPem, keyPem);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`[mTLS Relay] Running on port ${PORT}`);
});
