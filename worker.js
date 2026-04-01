/**
 * NDIS Fraud Intelligence — Cloudflare Worker
 * ==============================================
 * Environment variables required:
 *
 *   ABR_GUID          — ABR Web Services GUID (abr.business.gov.au)
 *   ALLOWED_ORIGIN    — GitHub Pages URL (e.g. https://jerrya-byte.github.io)
 *   ENTRA_TENANT_ID   — Same as SecureAuth app
 *   ENTRA_CLIENT_ID   — Same as SecureAuth app
 *
 * Routes (all require valid Entra Bearer token except OPTIONS):
 *   GET /api/providers         — NDIS Provider Register (cached 6h)
 *   GET /api/density           — Suburb density + dup contact clusters
 *   GET /api/kpis              — KPI summary counts
 *   GET /api/abn/:abn          — ABR lookup for a single ABN
 */

// ================================================================
//  CORS HEADERS
// ================================================================
function corsHeaders(env) {
  const origin = (env && env.ALLOWED_ORIGIN) ? env.ALLOWED_ORIGIN : '*';
  return {
    'Access-Control-Allow-Origin':  origin,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json',
  };
}

// ================================================================
//  ENTRA TOKEN VALIDATION
//  Validates the Bearer token issued by MSAL against Entra JWKS
// ================================================================
async function validateEntraToken(request, env) {
  // Skip validation if ENTRA_TENANT_ID not configured (dev/mock mode)
  if (!env.ENTRA_TENANT_ID || !env.ENTRA_CLIENT_ID) return { valid: true, dev: true };

  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return { valid: false, reason: 'Missing or malformed Authorization header' };
  }

  const token = authHeader.slice(7);

  try {
    // Decode JWT header to get kid
    const [headerB64] = token.split('.');
    const header = JSON.parse(atob(headerB64.replace(/-/g,'+').replace(/_/g,'/')));

    // Fetch Entra JWKS
    const jwksUrl = `https://login.microsoftonline.com/${env.ENTRA_TENANT_ID}/discovery/v2.0/keys`;
    const jwksRes = await fetch(jwksUrl, { cf: { cacheTtl: 3600 } });
    if (!jwksRes.ok) return { valid: false, reason: 'Could not fetch JWKS' };
    const { keys } = await jwksRes.json();

    const jwk = keys.find(k => k.kid === header.kid);
    if (!jwk) return { valid: false, reason: 'No matching signing key found' };

    // Import key and verify
    const cryptoKey = await crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false, ['verify']
    );

    const [, payloadB64, sigB64] = token.split('.');
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature    = Uint8Array.from(
      atob(sigB64.replace(/-/g,'+').replace(/_/g,'/')),
      c => c.charCodeAt(0)
    );

    const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, signingInput);
    if (!valid) return { valid: false, reason: 'Token signature invalid' };

    // Validate claims
    const payload = JSON.parse(atob(payloadB64.replace(/-/g,'+').replace(/_/g,'/')));
    const now     = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now)   return { valid: false, reason: 'Token expired' };
    if (payload.nbf && payload.nbf > now)   return { valid: false, reason: 'Token not yet valid' };
    if (payload.aud !== env.ENTRA_CLIENT_ID &&
        payload.aud !== `api://${env.ENTRA_CLIENT_ID}`) {
      // aud can also be 'https://graph.microsoft.com' for Graph tokens — allow those too
      if (!['https://graph.microsoft.com', 'https://graph.microsoft.com/'].includes(payload.aud)) {
        return { valid: false, reason: `Token audience mismatch: ${payload.aud}` };
      }
    }

    return { valid: true, user: { oid: payload.oid, upn: payload.upn || payload.preferred_username, name: payload.name } };

  } catch (err) {
    console.error('Token validation error:', err);
    return { valid: false, reason: `Validation error: ${err.message}` };
  }
}

function jsonResponse(data, env, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders(env),
  });
}

function errorResponse(msg, env, status = 500) {
  return jsonResponse({ error: msg }, env, status);
}

// ================================================================
//  ROUTER
// ================================================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(env) });
    }

    if (request.method !== 'GET') {
      return errorResponse('Method not allowed', env, 405);
    }

    // ── Validate Entra Bearer token ──────────────────────────────
    const authResult = await validateEntraToken(request, env);
    if (!authResult.valid) {
      return new Response(JSON.stringify({ error: 'Unauthorised', reason: authResult.reason }), {
        status: 401,
        headers: { ...corsHeaders(env), 'WWW-Authenticate': 'Bearer' },
      });
    }

    const path = url.pathname;

    try {
      if (path === '/api/providers') {
        return await handleProviders(env, ctx);
      }

      if (path === '/api/density') {
        return await handleDensity(env, ctx);
      }

      if (path === '/api/kpis') {
        return await handleKPIs(env, ctx);
      }

      const abnMatch = path.match(/^\/api\/abn\/(\d{11})$/);
      if (abnMatch) {
        return await handleABN(abnMatch[1], env);
      }

      return errorResponse('Not found', env, 404);

    } catch (err) {
      console.error('Worker error:', err);
      return errorResponse(`Internal error: ${err.message}`, env, 500);
    }
  }
};

// ================================================================
//  NDIS PROVIDER REGISTER
//  Source: data.gov.au NDIS Registered Providers dataset
//  The worker fetches the CSV, parses it, computes risk signals,
//  and caches the result in KV for 6 hours.
// ================================================================

// Public CSV download URL from data.gov.au
// Update this URL if the dataset moves — check: https://data.gov.au/dataset/registered-ndis-providers
const NDIS_PROVIDER_CSV_URL =
  'https://data.gov.au/data/dataset/registered-ndis-providers/resource/81a24768-ee1b-4eed-877a-0af62c01e284/download/registered-ndis-providers.csv';

const KV_PROVIDERS_KEY    = 'ndis_providers_v1';
const KV_DENSITY_KEY      = 'ndis_density_v1';
const KV_CACHE_TTL_SECS   = 6 * 60 * 60; // 6 hours

async function handleProviders(env, ctx) {
  // Try KV cache first
  if (env.NDIS_KV) {
    const cached = await env.NDIS_KV.get(KV_PROVIDERS_KEY, 'json');
    if (cached) return jsonResponse(cached, env);
  }

  const providers = await fetchAndParseProviders();

  // Cache in background
  if (env.NDIS_KV) {
    ctx.waitUntil(env.NDIS_KV.put(KV_PROVIDERS_KEY, JSON.stringify(providers), {
      expirationTtl: KV_CACHE_TTL_SECS
    }));
  }

  return jsonResponse(providers, env);
}

async function fetchAndParseProviders() {
  const res = await fetch(NDIS_PROVIDER_CSV_URL, {
    headers: { 'User-Agent': 'NDIS-Fraud-Intelligence/1.0' }
  });

  if (!res.ok) throw new Error(`NDIS CSV fetch failed: ${res.status}`);

  const csv = await res.text();
  const rows = parseCSV(csv);

  if (rows.length === 0) throw new Error('Empty NDIS provider CSV');

  const headers = rows[0].map(h => h.trim().toLowerCase().replace(/\s+/g, '_'));

  // Map header names to our expected fields
  // Actual CSV columns vary — this handles common variations
  const colMap = {
    abn:            findCol(headers, ['abn']),
    name:           findCol(headers, ['provider_name','name','registered_name']),
    state:          findCol(headers, ['state','state_territory','state/territory']),
    postcode:       findCol(headers, ['postcode','post_code']),
    suburb:         findCol(headers, ['suburb','town','locality']),
    phone:          findCol(headers, ['phone','telephone','phone_number']),
    email:          findCol(headers, ['email','email_address']),
    status:         findCol(headers, ['registration_status','status']),
    regDate:        findCol(headers, ['registration_date','registered_date','date_registered']),
    cancelDate:     findCol(headers, ['cancellation_date','cancelled_date','date_cancelled']),
  };

  const providers = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (!row || row.length < 3) continue;

    const abn     = colMap.abn !== -1     ? clean(row[colMap.abn])     : '';
    const name    = colMap.name !== -1    ? clean(row[colMap.name])    : '';
    const state   = colMap.state !== -1   ? clean(row[colMap.state]).toUpperCase() : '';
    const status  = colMap.status !== -1  ? clean(row[colMap.status])  : 'Active';

    if (!abn || !name) continue;

    providers.push({
      abn:        formatABN(abn),
      name:       name,
      state:      normaliseState(state),
      postcode:   colMap.postcode !== -1  ? clean(row[colMap.postcode])  : '',
      suburb:     colMap.suburb !== -1    ? clean(row[colMap.suburb])    : '',
      phone:      colMap.phone !== -1     ? clean(row[colMap.phone])     : '',
      email:      colMap.email !== -1     ? clean(row[colMap.email])     : '',
      status:     status,
      regDate:    colMap.regDate !== -1   ? clean(row[colMap.regDate])   : '',
      cancelDate: colMap.cancelDate !== -1 ? clean(row[colMap.cancelDate]) : '',
      // Risk signals computed later
      score:  0,
      level:  'low',
      flags:  [],
    });
  }

  return computeRiskScores(providers);
}

// ================================================================
//  RISK SCORING ENGINE
// ================================================================
function computeRiskScores(providers) {
  // Build lookup maps for cross-referencing
  const phoneMap = buildContactMap(providers, 'phone');
  const emailMap = buildContactMap(providers, 'email');

  // Postcode → provider count
  const postcodeCount = {};
  providers.forEach(p => {
    if (p.postcode) {
      postcodeCount[p.postcode] = (postcodeCount[p.postcode] || 0) + 1;
    }
  });

  // ABN prefix map: same first 9 digits = likely same entity
  const abnPrefixMap = {};
  providers.forEach(p => {
    const raw = p.abn.replace(/\s/g, '');
    if (raw.length === 11) {
      const prefix = raw.slice(0,9);
      if (!abnPrefixMap[prefix]) abnPrefixMap[prefix] = [];
      abnPrefixMap[prefix].push(p.abn);
    }
  });

  providers.forEach(p => {
    let score = 0;
    const flags = [];

    // 1. Duplicate phone/email across multiple ABNs
    const phoneMatches = p.phone ? (phoneMap[normalisePhone(p.phone)] || []) : [];
    const emailMatches = p.email ? (emailMap[p.email.toLowerCase()] || [])   : [];

    if (phoneMatches.length > 1) { score += 30; flags.push('dup-contact'); }
    if (emailMatches.length > 1) { score += 25; flags.push('dup-contact'); }

    // 2. Cancelled status (may still be queried if found via cross-ref)
    if (p.status && p.status.toLowerCase().includes('cancel')) { score += 20; }

    // 3. Provider density in postcode
    const pcCount = postcodeCount[p.postcode] || 0;
    if (pcCount > 50)      { score += 25; flags.push('density'); }
    else if (pcCount > 30) { score += 15; flags.push('density'); }
    else if (pcCount > 15) { score += 5; }

    // 4. Very new registration (< 6 months) — higher risk during warm-up period
    if (p.regDate) {
      const regMs = new Date(p.regDate).getTime();
      const ageMs = Date.now() - regMs;
      const sixMonths = 6 * 30 * 24 * 60 * 60 * 1000;
      if (!isNaN(regMs) && ageMs < sixMonths) { score += 10; }
    }

    // 5. Same ABN prefix appearing multiple times (re-registration pattern)
    const raw = p.abn.replace(/\s/g,'');
    if (raw.length === 11) {
      const prefix = raw.slice(0,9);
      if ((abnPrefixMap[prefix]||[]).length > 1) { score += 20; flags.push('abn-change'); }
    }

    p.score = Math.min(100, score);
    p.flags = [...new Set(flags)]; // deduplicate

    if      (p.score >= 80) p.level = 'critical';
    else if (p.score >= 60) p.level = 'high';
    else if (p.score >= 40) p.level = 'medium';
    else                    p.level = 'low';
  });

  // Return sorted by risk descending, limited to interesting providers
  return providers
    .sort((a, b) => b.score - a.score);
}

function buildContactMap(providers, field) {
  const map = {};
  providers.forEach(p => {
    if (!p[field]) return;
    const key = field === 'phone' ? normalisePhone(p[field]) : p[field].toLowerCase();
    if (!key) return;
    if (!map[key]) map[key] = [];
    map[key].push(p.abn);
  });
  return map;
}

function normalisePhone(phone) {
  return (phone || '').replace(/\D/g, '').replace(/^61/, '0');
}

// ================================================================
//  DENSITY ANALYSIS
// ================================================================

// ABS estimated resident population by suburb (SA2) — 2022 estimates
// Source: ABS Regional Population, 2021–22
// This is a curated subset of high-risk postcodes for initial analysis.
// Full dataset available at: https://api.data.abs.gov.au/
const SUBURB_POPULATION = {
  '2165': { name: 'Fairfield',     state: 'NSW', pop: 28000, lat: -33.8711, lng: 150.9553 },
  '2144': { name: 'Auburn',        state: 'NSW', pop: 22000, lat: -33.8493, lng: 151.0330 },
  '3175': { name: 'Dandenong',     state: 'VIC', pop: 24000, lat: -37.9878, lng: 145.2154 },
  '2163': { name: 'Villawood',     state: 'NSW', pop: 19000, lat: -33.8667, lng: 150.9833 },
  '2160': { name: 'Merrylands',    state: 'NSW', pop: 21000, lat: -33.8333, lng: 151.0000 },
  '3047': { name: 'Broadmeadows', state: 'VIC', pop: 23000, lat: -37.6833, lng: 144.9167 },
  '4114': { name: 'Logan Central', state: 'QLD', pop: 18000, lat: -27.6389, lng: 153.1078 },
  '2195': { name: 'Lakemba',       state: 'NSW', pop: 17000, lat: -33.9167, lng: 151.0667 },
  '2200': { name: 'Bankstown',     state: 'NSW', pop: 20000, lat: -33.9167, lng: 151.0333 },
  '3171': { name: 'Springvale',    state: 'VIC', pop: 16000, lat: -37.9500, lng: 145.1500 },
  '2166': { name: 'Cabramatta',    state: 'NSW', pop: 15000, lat: -33.8938, lng: 150.9407 },
  '3020': { name: 'Sunshine',      state: 'VIC', pop: 17000, lat: -37.7833, lng: 144.8333 },
};

// Expected providers per 10,000 population nationally (NDIS benchmark)
const EXPECTED_PROVIDERS_PER_10K = 7.8;

async function handleDensity(env, ctx) {
  if (env.NDIS_KV) {
    const cached = await env.NDIS_KV.get(KV_DENSITY_KEY, 'json');
    if (cached) return jsonResponse(cached, env);
  }

  let providers;
  try {
    providers = await fetchAndParseProviders();
  } catch(e) {
    return errorResponse(`Provider fetch failed: ${e.message}`, env);
  }

  // Count providers by postcode
  const pcCounts = {};
  providers.forEach(p => {
    if (p.postcode) pcCounts[p.postcode] = (pcCounts[p.postcode] || 0) + 1;
  });

  // Build suburb density data
  const suburbs = Object.entries(SUBURB_POPULATION).map(([postcode, meta]) => {
    const actual   = pcCounts[postcode] || 0;
    const expected = Math.round((meta.pop / 10000) * EXPECTED_PROVIDERS_PER_10K);
    const ratio    = expected > 0 ? Math.round((actual / expected) * 100) / 100 : 0;
    return {
      postcode, ...meta,
      providers: actual,
      expected,
      ratio,
    };
  }).filter(s => s.providers > 0).sort((a, b) => b.ratio - a.ratio);

  // Build duplicate contact clusters
  const phoneMap = buildContactMap(providers.filter(p=>p.phone), 'phone');
  const emailMap = buildContactMap(providers.filter(p=>p.email), 'email');

  const clusters = [];

  Object.entries(phoneMap)
    .filter(([, abns]) => abns.length > 1)
    .slice(0, 20) // cap at 20 clusters
    .forEach(([phone, abns]) => {
      const entries = abns.map(abn => {
        const p = providers.find(x => x.abn === abn);
        return { name: p?.name || abn, abn, status: p?.status?.toLowerCase().includes('cancel') ? 'cancelled' : 'active' };
      });
      clusters.push({ contact: maskPhone(phone), type: 'Mobile', entries });
    });

  Object.entries(emailMap)
    .filter(([, abns]) => abns.length > 1)
    .slice(0, 10)
    .forEach(([email, abns]) => {
      const entries = abns.map(abn => {
        const p = providers.find(x => x.abn === abn);
        return { name: p?.name || abn, abn, status: p?.status?.toLowerCase().includes('cancel') ? 'cancelled' : 'active' };
      });
      clusters.push({ contact: maskEmail(email), type: 'Email', entries });
    });

  const result = { suburbs, clusters };

  if (env.NDIS_KV) {
    ctx.waitUntil(env.NDIS_KV.put(KV_DENSITY_KEY, JSON.stringify(result), {
      expirationTtl: KV_CACHE_TTL_SECS
    }));
  }

  return jsonResponse(result, env);
}

// ================================================================
//  KPIs
// ================================================================
async function handleKPIs(env, ctx) {
  let providers;
  try {
    providers = await fetchAndParseProviders();
  } catch(e) {
    return errorResponse(`KPI fetch failed: ${e.message}`, env);
  }

  const phoneMap = buildContactMap(providers.filter(p=>p.phone), 'phone');
  const dupCount = Object.values(phoneMap).filter(a => a.length > 1).length;

  return jsonResponse({
    total:   providers.length,
    flagged: providers.filter(p => p.score >= 60).length,
    dup:     dupCount,
    rereg:   providers.filter(p => p.flags.includes('abn-change')).length,
    density: providers.filter(p => p.flags.includes('density')).length,
  }, env);
}

// ================================================================
//  ABR ABN LOOKUP
// ================================================================
async function handleABN(abn, env) {
  if (!env.ABR_GUID) {
    return errorResponse('ABR_GUID environment variable not configured. Set it in your Worker settings.', env, 503);
  }

  const url = `https://abr.business.gov.au/abrxmlsearch/AbrXmlSearch.asmx/SearchByABN` +
    `?searchString=${abn}&includeHistoricalDetails=Y&authenticationGuid=${env.ABR_GUID}`;

  const res = await fetch(url, {
    headers: { 'Accept': 'application/xml' }
  });

  if (!res.ok) throw new Error(`ABR API returned ${res.status}`);

  const xml  = await res.text();
  const data = parseABRXML(xml, abn);

  // Cross-reference against our provider dataset if available
  try {
    let providers = [];
    if (env.NDIS_KV) {
      const cached = await env.NDIS_KV.get(KV_PROVIDERS_KEY, 'json');
      if (cached) providers = cached;
    }

    const rawABN = abn.replace(/\s/g, '');
    const thisProvider = providers.find(p => p.abn.replace(/\s/g,'') === rawABN);

    if (thisProvider) {
      // Attach cross-refs: other providers sharing same phone/email
      const phoneMap = buildContactMap(providers.filter(p=>p.phone), 'phone');
      const emailMap = buildContactMap(providers.filter(p=>p.email), 'email');

      const relatedABNs = new Set();
      if (thisProvider.phone) {
        const key = normalisePhone(thisProvider.phone);
        (phoneMap[key] || []).forEach(a => relatedABNs.add(a));
      }
      if (thisProvider.email) {
        const key = thisProvider.email.toLowerCase();
        (emailMap[key] || []).forEach(a => relatedABNs.add(a));
      }
      relatedABNs.delete(thisProvider.abn);

      data.crossRefs = [...relatedABNs].map(a => {
        const p = providers.find(x => x.abn === a);
        return {
          abn: a,
          name: p?.name || a,
          reason: 'Shared contact details',
          status: p?.status?.toLowerCase().includes('cancel') ? 'cancelled' : 'active',
          riskScore: p?.score || 0,
        };
      });

      data.riskScore  = thisProvider.score;
      data.riskLevel  = thisProvider.level;
      data.flags      = thisProvider.flags;
      data.riskFactors = buildRiskFactors(thisProvider);
    }
  } catch (e) {
    console.warn('Cross-ref enrichment failed:', e);
  }

  return jsonResponse(data, env);
}

function parseABRXML(xml, abnRaw) {
  // Basic XML field extraction (no DOM parser in Workers — use regex carefully)
  const get = (tag) => {
    const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)<\/${tag}>`, 'i'));
    return m ? m[1].trim() : '';
  };

  const getAll = (tag) => {
    const matches = [];
    const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\/${tag}>`, 'gi');
    let m;
    while ((m = re.exec(xml)) !== null) matches.push(m[1]);
    return matches;
  };

  // ABR response fields
  const name    = get('organisationName') || get('mainName') || get('otherTradingName') || 'Unknown';
  const status  = get('entityStatusCode') || 'Unknown';
  const type    = get('entityTypeCode') || '';
  const state   = get('mainBusinessPhysicalAddressStateCode') || '';
  const postcode = get('mainBusinessPhysicalAddressPostCode') || '';

  // Historical records
  const history = [];

  // Entity status history
  const statusRecords = getAll('entityStatus');
  statusRecords.forEach(block => {
    const code   = (block.match(/<entityStatusCode>([^<]+)/) || [])[1] || '';
    const from   = (block.match(/<effectiveFrom>([^<]+)/)    || [])[1] || '';
    if (from) {
      history.push({
        type: code.toLowerCase().includes('cancel') ? 'cancel' : 'register',
        date: formatDate(from),
        event: `Entity status: ${code || 'Updated'}`
      });
    }
  });

  // Business name history
  const nameRecords = getAll('mainName');
  nameRecords.forEach(block => {
    const orgName = (block.match(/<organisationName>([^<]+)/) || [])[1] || '';
    const from    = (block.match(/<effectiveFrom>([^<]+)/)    || [])[1] || '';
    if (orgName && from) {
      history.push({ type: 'namechange', date: formatDate(from), event: `Business name: ${orgName}` });
    }
  });

  // Trading names
  const tradingNames = getAll('otherTradingName');
  tradingNames.forEach(block => {
    const orgName = (block.match(/<organisationName>([^<]+)/) || [])[1] || '';
    const from    = (block.match(/<effectiveFrom>([^<]+)/)    || [])[1] || '';
    if (orgName && from) {
      history.push({ type: 'namechange', date: formatDate(from), event: `Trading name: ${orgName}` });
    }
  });

  history.sort((a, b) => new Date(a.date) - new Date(b.date));

  const formatted = formatABN(abnRaw);

  return {
    abn:          formatted,
    name:         name,
    type:         entityTypeLabel(type),
    state:        normaliseState(state),
    postcode:     postcode,
    suburb:       '',
    status:       status.toLowerCase().includes('cancel') ? 'Cancelled' : 'Active',
    gstRegistered: xml.includes('<goodsAndServicesTax>') ? (xml.includes('<effectiveTo>') ? 'No' : 'Yes') : 'Unknown',
    registeredDate: history.length > 0 ? history[0].date : 'Unknown',
    lastUpdated:  formatDate(get('lastUpdatedDate')),
    history,
    crossRefs:    [],
    riskScore:    0,
    riskLevel:    'low',
    flags:        [],
    riskFactors:  [],
  };
}

function buildRiskFactors(p) {
  const factors = [];
  if (p.flags.includes('dup-contact'))  factors.push({ label: 'Duplicate contact across multiple ABNs', severity: 'critical' });
  if (p.flags.includes('reregistered')) factors.push({ label: 'Previously cancelled ABNs linked to same operator', severity: 'critical' });
  if (p.flags.includes('density'))      factors.push({ label: 'Provider located in high-density fraud hotspot suburb', severity: 'high' });
  if (p.flags.includes('abn-change'))   factors.push({ label: 'Multiple ABN registrations detected (same entity)', severity: 'high' });
  if (p.flags.includes('no-service'))   factors.push({ label: 'Claims submitted with no participant match on file', severity: 'high' });
  return factors;
}

// ================================================================
//  CSV PARSER
// ================================================================
function parseCSV(text) {
  const rows = [];
  const lines = text.split('\n');
  for (const line of lines) {
    if (!line.trim()) continue;
    const row = [];
    let field = '';
    let inQuote = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuote && line[i+1] === '"') { field += '"'; i++; }
        else inQuote = !inQuote;
      } else if (ch === ',' && !inQuote) {
        row.push(field.trim()); field = '';
      } else {
        field += ch;
      }
    }
    row.push(field.trim());
    rows.push(row);
  }
  return rows;
}

// ================================================================
//  HELPERS
// ================================================================
function findCol(headers, candidates) {
  for (const c of candidates) {
    const idx = headers.indexOf(c);
    if (idx !== -1) return idx;
    // Partial match
    const partial = headers.findIndex(h => h.includes(c));
    if (partial !== -1) return partial;
  }
  return -1;
}

function clean(s) {
  return (s || '').replace(/^["']|["']$/g, '').trim();
}

function formatABN(raw) {
  const d = (raw || '').replace(/\D/g, '');
  if (d.length !== 11) return raw || '';
  return `${d.slice(0,2)} ${d.slice(2,5)} ${d.slice(5,8)} ${d.slice(8)}`;
}

function normaliseState(s) {
  const map = { 'NEW SOUTH WALES':'NSW','VICTORIA':'VIC','QUEENSLAND':'QLD',
    'WESTERN AUSTRALIA':'WA','SOUTH AUSTRALIA':'SA','TASMANIA':'TAS',
    'NORTHERN TERRITORY':'NT','AUSTRALIAN CAPITAL TERRITORY':'ACT' };
  return map[s.toUpperCase()] || s.toUpperCase().slice(0,3);
}

function entityTypeLabel(code) {
  const map = { 'PRV':'Australian Private Company','PUB':'Australian Public Company',
    'IND':'Individual/Sole Trader','TRU':'Trust','PTR':'Partnership',
    'GOV':'Government Entity','OTH':'Other Entity' };
  return map[code] || code || 'Unknown';
}

function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleDateString('en-AU', { day:'2-digit', month:'short', year:'numeric' });
}

function maskPhone(phone) {
  const p = (phone || '').replace(/\D/g, '');
  if (p.length >= 10) return `${p.slice(0,4)} *** ${p.slice(-3)}`;
  return phone;
}

function maskEmail(email) {
  const [user, domain] = (email || '').split('@');
  if (!domain) return email;
  return `${user.slice(0,3)}***@${domain}`;
}
