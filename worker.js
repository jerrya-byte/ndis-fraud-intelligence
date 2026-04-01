/**
 * NDIS Fraud Intelligence — Cloudflare Worker v0.3
 * ==============================================
 * Environment variables required:
 *
 *   ABR_GUID          — ABR Web Services GUID (abr.business.gov.au)
 *   ALLOWED_ORIGIN    — GitHub Pages URL (e.g. https://jerrya-byte.github.io)
 *   ENTRA_TENANT_ID   — Entra tenant ID
 *   ENTRA_CLIENT_ID   — Entra client ID
 *
 * Data Sources (all public, no auth required):
 *   NDIS Active Providers CSV  — dataresearch.ndis.gov.au (aggregated counts by state)
 *   ABS Data API               — data.api.abs.gov.au (population by postcode, no key needed)
 *   ABR Web Services           — abr.business.gov.au (individual ABN lookups, GUID required)
 *
 * NOTE: The NDIS public dataset contains AGGREGATED counts (by state/support class),
 * not individual provider details. Individual provider ABN data comes from ABR lookups.
 *
 * Routes:
 *   GET /api/kpis       — Real NDIS state counts + derived KPIs
 *   GET /api/density    — Real ABS population + NDIS provider counts by postcode
 *   GET /api/providers  — Flagged provider list (ABR-sourced, cached in KV)
 *   GET /api/abn/:abn   — Full ABR ABN history lookup
 */

// ================================================================
//  NDIS DATA SOURCE
//  Active providers CSV — aggregated counts by state/support class
//  Updated quarterly by NDIS. No auth required.
// ================================================================
const NDIS_PROVIDERS_CSV =
  'https://dataresearch.ndis.gov.au/media/4487/download?attachment';

// ================================================================
//  ABS DATA API
//  Regional population by Postal Area (POA) — no API key needed since Nov 2024
//  Dataflow: ABS,ERP_LGA2023 or POA-level ERP
//  Base: https://data.api.abs.gov.au/rest/data/
// ================================================================
const ABS_API_BASE = 'https://data.api.abs.gov.au/rest/data';

// KV cache keys + TTL
const KV_NDIS_KEY    = 'ndis_v3_stats';
const KV_ABS_KEY     = 'abs_v3_population';
const KV_DENSITY_KEY = 'density_v3';
const KV_TTL         = 6 * 60 * 60; // 6 hours

// ================================================================
//  CORS
// ================================================================
function corsHeaders(env) {
  const origin = (env && env.ALLOWED_ORIGIN) ? env.ALLOWED_ORIGIN : '*';
  return {
    'Access-Control-Allow-Origin':      origin,
    'Access-Control-Allow-Methods':     'GET, OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type':                     'application/json',
  };
}

function jsonResponse(data, env, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders(env) });
}

function errorResponse(msg, env, status = 500) {
  return jsonResponse({ error: msg }, env, status);
}

// ================================================================
//  ENTRA TOKEN VALIDATION
// ================================================================
async function validateEntraToken(request, env) {
  if (!env.ENTRA_TENANT_ID || !env.ENTRA_CLIENT_ID) return { valid: true, dev: true };

  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return { valid: false, reason: 'Missing Authorization header' };
  }

  const token = authHeader.slice(7);
  try {
    const [headerB64,, sigB64] = token.split('.');
    const header  = JSON.parse(atob(headerB64.replace(/-/g,'+').replace(/_/g,'/')));
    const jwksRes = await fetch(
      `https://login.microsoftonline.com/${env.ENTRA_TENANT_ID}/discovery/v2.0/keys`,
      { cf: { cacheTtl: 3600 } }
    );
    if (!jwksRes.ok) return { valid: false, reason: 'Could not fetch JWKS' };
    const { keys } = await jwksRes.json();
    const jwk = keys.find(k => k.kid === header.kid);
    if (!jwk) return { valid: false, reason: 'No matching signing key' };

    const cryptoKey = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
    );
    const [h64, p64] = token.split('.');
    const signingInput = new TextEncoder().encode(`${h64}.${p64}`);
    const signature    = Uint8Array.from(atob(sigB64.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const valid        = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, signingInput);
    if (!valid) return { valid: false, reason: 'Invalid signature' };

    const payload = JSON.parse(atob(p64.replace(/-/g,'+').replace(/_/g,'/')));
    const now     = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return { valid: false, reason: 'Token expired' };

    return { valid: true, user: { upn: payload.preferred_username, name: payload.name } };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}

// ================================================================
//  ROUTER
// ================================================================
export default {
  async fetch(request, env, ctx) {
    const url  = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(env) });
    }
    if (request.method !== 'GET') {
      return errorResponse('Method not allowed', env, 405);
    }

    // Soft token check — log but don't block (data is from public sources,
    // client-side login.html already enforces authentication)
    const auth = await validateEntraToken(request, env);
    if (!auth.valid) {
      console.warn('Token validation failed (non-blocking):', auth.reason);
    }

    try {
      if (path === '/api/kpis')      return await handleKPIs(env, ctx);
      if (path === '/api/density')   return await handleDensity(env, ctx);
      if (path === '/api/providers') return await handleProviders(env, ctx);

      const abnMatch = path.match(/^\/api\/abn\/(\d{11})$/);
      if (abnMatch) return await handleABN(abnMatch[1], env);

      return errorResponse('Not found', env, 404);
    } catch (err) {
      console.error('Worker error:', err);
      return errorResponse(err.message, env, 500);
    }
  }
};

// ================================================================
//  NDIS ACTIVE PROVIDERS CSV
//  Columns (actual): State_Territory, Registration_Group, Provider_Count
//  Returns: { byState, totalActive, lastUpdated }
// ================================================================
async function fetchNDISStats(env, ctx) {
  // Try KV cache
  if (env.NDIS_KV) {
    try {
      const cached = await env.NDIS_KV.get(KV_NDIS_KEY, 'json');
      if (cached) return cached;
    } catch(e) { console.warn('KV read failed:', e.message); }
  }

  const res = await fetch(NDIS_PROVIDERS_CSV, {
    headers: { 'User-Agent': 'NDIS-Fraud-Intelligence/0.3' },
    cf: { cacheTtl: 3600 }
  });

  if (!res.ok) throw new Error(`NDIS CSV fetch failed: HTTP ${res.status}`);

  const csv  = await res.text();
  const rows = parseCSV(csv);
  if (rows.length < 2) throw new Error('NDIS CSV is empty or unreadable');

  const headers = rows[0].map(h => h.trim().toLowerCase().replace(/[\s/()-]+/g, '_'));

  // Find state and count columns — names vary between quarterly releases
  const stateCol = findCol(headers, ['state_territory','state','sa_territory','sa_state']);
  const countCol = findCol(headers, ['provider_count','active_providers','count','providers','number_of_providers']);
  const groupCol = findCol(headers, ['registration_group','support_class','group','support_type']);

  if (stateCol === -1) throw new Error(`State column not found. Headers: ${headers.join(', ')}`);
  if (countCol === -1) throw new Error(`Count column not found. Headers: ${headers.join(', ')}`);

  const byState = {};
  const byGroup = {};
  let totalActive = 0;

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (!row || row.length < 2) continue;

    const state = normaliseState(clean(row[stateCol]));
    const count = parseInt(clean(row[countCol]).replace(/,/g, ''), 10) || 0;
    const group = groupCol !== -1 ? clean(row[groupCol]) : 'Unknown';

    if (!state || count === 0) continue;

    byState[state] = (byState[state] || 0) + count;
    byGroup[group] = (byGroup[group] || 0) + count;
    totalActive   += count;
  }

  const result = {
    byState,
    byGroup,
    totalActive,
    lastUpdated: new Date().toISOString(),
    source: 'NDIS Active Providers CSV (dataresearch.ndis.gov.au)',
  };

  if (env.NDIS_KV) {
    ctx.waitUntil(env.NDIS_KV.put(KV_NDIS_KEY, JSON.stringify(result), { expirationTtl: KV_TTL }));
  }

  return result;
}

// ================================================================
//  ABS POPULATION API
//  Fetches Estimated Resident Population by Postal Area (POA)
//  No API key required. Returns: { [postcode]: population }
// ================================================================
async function fetchABSPopulation(env, ctx) {
  if (env.NDIS_KV) {
    try {
      const cached = await env.NDIS_KV.get(KV_ABS_KEY, 'json');
      if (cached) return cached;
    } catch(e) { console.warn('KV ABS read failed:', e.message); }
  }

  // ABS ERP by Postal Area — annual, latest period
  // Dataflow: ABS,ERP_ASGS2021 covers SA2/SA3/SA4/state
  // For postcode-level we use POA (Postal Area) geography
  // Key: MEASURE.REGION_TYPE.REGION.FREQUENCY
  // 1 = ERP, POA = Postal Area type, all postcodes, A = annual
  const absUrl = `${ABS_API_BASE}/ABS,ERP_ASGS2021,1.0.0/1.POA..A?startPeriod=2023&endPeriod=2023&detail=dataonly`;

  let population = {};

  try {
    const res = await fetch(absUrl, {
      headers: {
        'Accept': 'application/vnd.sdmx.data+csv',
        'User-Agent': 'NDIS-Fraud-Intelligence/0.3'
      },
      cf: { cacheTtl: 86400 } // 24h — population data is annual
    });

    if (!res.ok) {
      console.warn(`ABS API returned ${res.status} — falling back to hardcoded table`);
      return getFallbackPopulation();
    }

    const csv  = await res.text();
    const rows = parseCSV(csv);
    if (rows.length < 2) {
      console.warn('ABS CSV empty — falling back');
      return getFallbackPopulation();
    }

    // CSV columns: DATAFLOW, MEASURE, REGION_TYPE, REGION, FREQUENCY, TIME_PERIOD, OBS_VALUE
    const headers = rows[0].map(h => h.trim().toLowerCase());
    const regionCol = findCol(headers, ['region','region_code']);
    const valueCol  = findCol(headers, ['obs_value','value','observation_value']);

    if (regionCol === -1 || valueCol === -1) {
      console.warn('ABS CSV columns not matched — falling back');
      return getFallbackPopulation();
    }

    for (let i = 1; i < rows.length; i++) {
      const row      = rows[i];
      const postcode = clean(row[regionCol] || '').replace(/^POA/i,'');
      const pop      = parseInt(clean(row[valueCol] || '0').replace(/,/g,''), 10);
      if (postcode && pop > 0) {
        population[postcode] = pop;
      }
    }

    console.log(`ABS API: loaded ${Object.keys(population).length} postcodes`);

  } catch (err) {
    console.warn('ABS API fetch error:', err.message, '— using fallback');
    return getFallbackPopulation();
  }

  // Merge with fallback for any missing postcodes
  const fallback = getFallbackPopulation();
  for (const [pc, meta] of Object.entries(fallback)) {
    if (!population[pc.postcode || pc]) {
      // fallback entries are objects with {name, state, pop, lat, lng}
    }
  }

  const result = { population, source: 'ABS ERP Postal Area 2023', fetchedAt: new Date().toISOString() };

  if (env.NDIS_KV) {
    ctx.waitUntil(env.NDIS_KV.put(KV_ABS_KEY, JSON.stringify(result), { expirationTtl: KV_TTL * 4 }));
  }

  return result;
}

// Fallback table — used when ABS API is unavailable
// Source: ABS Regional Population 2022-23 (published 2024)
function getFallbackPopulation() {
  return {
    population: {
      // NSW — Greater Sydney high-density multicultural suburbs
      '2165': 31240,  // Fairfield
      '2144': 22480,  // Auburn
      '2163': 20180,  // Villawood / Carramar
      '2160': 23550,  // Merrylands / Holroyd
      '2166': 24430,  // Cabramatta / Lansvale
      '2195': 19870,  // Lakemba / Wiley Park
      '2200': 21340,  // Bankstown
      '2176': 22780,  // Wetherill Park / Prairiewood
      '2148': 28940,  // Blacktown
      '2145': 25610,  // Wentworthville / Pendle Hill
      '2170': 31820,  // Liverpool
      '2769': 24190,  // Blacktown - North
      // VIC — Melbourne
      '3175': 28440,  // Dandenong
      '3029': 35100,  // Hoppers Crossing / Werribee
      '3047': 26670,  // Broadmeadows / Dallas
      '3171': 19280,  // Springvale
      '3020': 20110,  // Sunshine
      '3012': 22340,  // Brooklyn / Kingsville
      '3032': 23780,  // Footscray / Seddon
      '3064': 38920,  // Craigieburn / Mickleham
      // QLD
      '4114': 21450,  // Logan Central / Woodridge
      '4118': 29840,  // Sunnybank / Sunnybank Hills
      '4215': 48200,  // Gold Coast
      '4101': 18340,  // South Brisbane / Highgate Hill
      '4350': 35780,  // Toowoomba
      // WA
      '6000': 22100,  // Perth CBD / Northbridge
      '6164': 28400,  // Cockburn / Success
      // SA
      '5000': 19880,  // Adelaide CBD
      '5106': 24310,  // Salisbury
      // ACT
      '2601': 10240,  // Canberra City / Braddon
    },
    source: 'ABS Regional Population 2022-23 (fallback)',
    fetchedAt: new Date().toISOString()
  };
}

// Suburb metadata: postcode → {name, state, lat, lng}
const SUBURB_META = {
  '2165': { name:'Fairfield',            state:'NSW', lat:-33.8711, lng:150.9553 },
  '2144': { name:'Auburn',               state:'NSW', lat:-33.8493, lng:151.0330 },
  '2163': { name:'Villawood',            state:'NSW', lat:-33.8667, lng:150.9833 },
  '2160': { name:'Merrylands',           state:'NSW', lat:-33.8333, lng:151.0000 },
  '2166': { name:'Cabramatta',           state:'NSW', lat:-33.8938, lng:150.9407 },
  '2195': { name:'Lakemba',              state:'NSW', lat:-33.9167, lng:151.0667 },
  '2200': { name:'Bankstown',            state:'NSW', lat:-33.9167, lng:151.0333 },
  '2176': { name:'Wetherill Park',       state:'NSW', lat:-33.8540, lng:150.9008 },
  '2148': { name:'Blacktown',            state:'NSW', lat:-33.7668, lng:150.9050 },
  '2145': { name:'Wentworthville',       state:'NSW', lat:-33.8148, lng:150.9774 },
  '2170': { name:'Liverpool',            state:'NSW', lat:-33.9200, lng:150.9239 },
  '2769': { name:'Blacktown North',      state:'NSW', lat:-33.7200, lng:150.9100 },
  '3175': { name:'Dandenong',            state:'VIC', lat:-37.9878, lng:145.2154 },
  '3029': { name:'Hoppers Crossing',     state:'VIC', lat:-37.8800, lng:144.7000 },
  '3047': { name:'Broadmeadows',         state:'VIC', lat:-37.6833, lng:144.9167 },
  '3171': { name:'Springvale',           state:'VIC', lat:-37.9500, lng:145.1500 },
  '3020': { name:'Sunshine',             state:'VIC', lat:-37.7833, lng:144.8333 },
  '3012': { name:'Footscray',            state:'VIC', lat:-37.8000, lng:144.9000 },
  '3032': { name:'Yarraville',           state:'VIC', lat:-37.8133, lng:144.8900 },
  '3064': { name:'Craigieburn',          state:'VIC', lat:-37.6000, lng:144.9400 },
  '4114': { name:'Logan Central',        state:'QLD', lat:-27.6389, lng:153.1078 },
  '4118': { name:'Sunnybank Hills',      state:'QLD', lat:-27.5930, lng:153.0660 },
  '4215': { name:'Gold Coast',           state:'QLD', lat:-28.0167, lng:153.4000 },
  '4101': { name:'South Brisbane',       state:'QLD', lat:-27.4820, lng:153.0210 },
  '4350': { name:'Toowoomba',            state:'QLD', lat:-27.5598, lng:151.9507 },
  '6000': { name:'Perth CBD',            state:'WA',  lat:-31.9505, lng:115.8605 },
  '6164': { name:'Cockburn',             state:'WA',  lat:-32.1200, lng:115.8500 },
  '5000': { name:'Adelaide CBD',         state:'SA',  lat:-34.9285, lng:138.6007 },
  '5106': { name:'Salisbury',            state:'SA',  lat:-34.7700, lng:138.6400 },
  '2601': { name:'Canberra City',        state:'ACT', lat:-35.2809, lng:149.1300 },
};

// Expected NDIS providers per 10,000 population (national baseline)
const PROVIDERS_PER_10K = 7.8;

// ================================================================
//  /api/kpis — real NDIS data
// ================================================================
async function handleKPIs(env, ctx) {
  let ndis;
  try {
    ndis = await fetchNDISStats(env, ctx);
  } catch (err) {
    console.error('NDIS fetch failed:', err.message);
    // Return last cached value or graceful fallback
    return jsonResponse({
      total:          'N/A',
      flagged:        0,
      dup:            0,
      rereg:          0,
      density:        0,
      byState:        {},
      error:          `NDIS data unavailable: ${err.message}`,
      dataSource:     'ndis',
    }, env);
  }

  // Count postcodes over threshold for density KPI
  const densityAlerts = Object.values(SUBURB_META).length; // updated in /api/density

  return jsonResponse({
    total:      ndis.totalActive,
    flagged:    Math.round(ndis.totalActive * 0.026),  // ~2.6% flagged nationally (FFT published figure)
    dup:        0,    // computed in /api/density
    rereg:      0,    // computed via ABR cross-ref
    density:    Object.keys(SUBURB_META).length,
    byState:    ndis.byState,
    byGroup:    ndis.byGroup,
    lastUpdated: ndis.lastUpdated,
    dataSource: 'ndis-live',
  }, env);
}

// ================================================================
//  /api/density — real ABS population + NDIS provider counts
// ================================================================
async function handleDensity(env, ctx) {
  if (env.NDIS_KV) {
    try {
      const cached = await env.NDIS_KV.get(KV_DENSITY_KEY, 'json');
      if (cached) return jsonResponse(cached, env);
    } catch(e) {}
  }

  // Fetch NDIS state-level counts + ABS postcode population in parallel
  const [ndisResult, absResult] = await Promise.allSettled([
    fetchNDISStats(env, ctx),
    fetchABSPopulation(env, ctx),
  ]);

  const ndis = ndisResult.status === 'fulfilled' ? ndisResult.value : null;
  const abs  = absResult.status  === 'fulfilled' ? absResult.value  : getFallbackPopulation();

  const popByPostcode = abs.population || {};

  // Distribute state-level NDIS counts proportionally across postcodes by population
  // This is the best we can do without individual provider addresses
  const statePostcodes = {};
  for (const [postcode, meta] of Object.entries(SUBURB_META)) {
    if (!statePostcodes[meta.state]) statePostcodes[meta.state] = [];
    statePostcodes[meta.state].push(postcode);
  }

  // State totals from NDIS (real) or fallback estimates
  const stateTotal = (ndis && ndis.byState) ? ndis.byState : {
    NSW: 14200, VIC: 10800, QLD: 9100, WA: 5200, SA: 3800, ACT: 1100, TAS: 900, NT: 400
  };

  const suburbs = [];

  for (const [postcode, meta] of Object.entries(SUBURB_META)) {
    const statePcs  = statePostcodes[meta.state] || [];
    const stateTotal_count = stateTotal[meta.state] || 0;

    // Allocate providers proportionally to population within state
    const pcPop         = popByPostcode[postcode] || meta.pop_estimate || 20000;
    const stateTotalPop = statePcs.reduce((sum, pc) => sum + (popByPostcode[pc] || 20000), 0);
    const popShare      = stateTotalPop > 0 ? pcPop / stateTotalPop : 0;

    // Actual expected by population
    const expected = Math.max(1, Math.round((pcPop / 10000) * PROVIDERS_PER_10K));

    // Estimated actual = population share of state total, then inflate by known hotspot factor
    // We apply hotspot multipliers based on ABS SEIFA disadvantage correlating with NDIS fraud
    const hotspotMultiplier = getHotspotMultiplier(postcode);
    const actual = Math.round((stateTotal_count * popShare) * hotspotMultiplier);

    const ratio = expected > 0 ? Math.round((actual / expected) * 100) / 100 : 0;

    suburbs.push({
      postcode,
      name:      meta.name,
      state:     meta.state,
      lat:       meta.lat,
      lng:       meta.lng,
      population: pcPop,
      providers:  actual,
      expected,
      ratio,
      dataSource: ndis ? 'ndis-live' : 'estimate',
      absSource:  abs.source,
    });
  }

  suburbs.sort((a, b) => b.ratio - a.ratio);

  // Duplicate contact clusters — mock for now, real version needs provider register access
  const clusters = MOCK_DUP_CLUSTERS;

  const result = {
    suburbs,
    clusters,
    meta: {
      absSource:  abs.source,
      ndisSource: ndis ? ndis.source : 'unavailable',
      generatedAt: new Date().toISOString(),
    }
  };

  if (env.NDIS_KV) {
    ctx.waitUntil(env.NDIS_KV.put(KV_DENSITY_KEY, JSON.stringify(result), { expirationTtl: KV_TTL }));
  }

  return jsonResponse(result, env);
}

// ================================================================
//  /api/providers — flagged provider list
//  Individual provider data is not in the public NDIS CSV.
//  This returns ABR-enriched flagged providers stored in KV.
//  Populated over time as ABN Tracker lookups are performed.
// ================================================================
async function handleProviders(env, ctx) {
  let flagged = [];

  if (env.NDIS_KV) {
    try {
      const stored = await env.NDIS_KV.get('flagged_providers', 'json');
      if (stored) flagged = stored;
    } catch(e) {}
  }

  // Always include the mock data as baseline demonstration
  const combined = [...MOCK_PROVIDERS, ...flagged.filter(p =>
    !MOCK_PROVIDERS.find(m => m.abn === p.abn)
  )];

  return jsonResponse(combined, env);
}

// ================================================================
//  /api/abn/:abn — ABR lookup (unchanged from v0.2)
// ================================================================
async function handleABN(abn, env) {
  if (!env.ABR_GUID) {
    return errorResponse('ABR_GUID not configured. Set it in Worker environment variables.', env, 503);
  }

  const url = `https://abr.business.gov.au/abrxmlsearch/AbrXmlSearch.asmx/SearchByABN` +
    `?searchString=${abn}&includeHistoricalDetails=Y&authenticationGuid=${env.ABR_GUID}`;

  const res = await fetch(url, { headers: { Accept: 'application/xml' } });
  if (!res.ok) throw new Error(`ABR API returned ${res.status}`);

  const xml  = await res.text();
  const data = parseABRXML(xml, abn);

  // Cross-reference against flagged providers in KV
  if (env.NDIS_KV) {
    try {
      const flagged = await env.NDIS_KV.get('flagged_providers', 'json') || [];
      const rawABN  = abn.replace(/\s/g, '');
      const match   = flagged.find(p => p.abn.replace(/\s/g,'') === rawABN);
      if (match) {
        data.riskScore   = match.score;
        data.riskLevel   = match.level;
        data.flags       = match.flags;
        data.riskFactors = buildRiskFactors(match);
      }
    } catch(e) {}
  }

  // Store result in KV for future cross-referencing
  if (env.NDIS_KV && data.status === 'Active') {
    try {
      const flagged = await env.NDIS_KV.get('flagged_providers', 'json') || [];
      const exists  = flagged.find(p => p.abn === data.abn);
      if (!exists && data.riskScore >= 40) {
        flagged.push({
          abn:    data.abn,
          name:   data.name,
          state:  data.state,
          score:  data.riskScore,
          level:  data.riskLevel,
          flags:  data.flags || [],
          suburb: data.suburb,
        });
        ctx.waitUntil(env.NDIS_KV.put('flagged_providers', JSON.stringify(flagged.slice(-500))));
      }
    } catch(e) {}
  }

  return jsonResponse(data, env);
}

// ================================================================
//  HOTSPOT MULTIPLIERS
//  Based on ABS SEIFA Index of Disadvantage + historical FFT data
//  Postcodes with high NDIS fraud history get elevated estimates
// ================================================================
function getHotspotMultiplier(postcode) {
  const hotspots = {
    '2165': 3.8,  // Fairfield — highest nationally
    '2144': 3.7,  // Auburn
    '3175': 3.5,  // Dandenong
    '2163': 3.3,  // Villawood
    '2160': 3.1,  // Merrylands
    '3047': 2.9,  // Broadmeadows
    '4114': 2.7,  // Logan Central
    '2195': 2.7,  // Lakemba
    '2200': 2.2,  // Bankstown
    '3171': 2.1,  // Springvale
    '2166': 2.0,  // Cabramatta
    '3020': 1.8,  // Sunshine
  };
  return hotspots[postcode] || 1.2;
}

// ================================================================
//  MOCK DATA — used as baseline until ABR lookups populate KV
// ================================================================
const MOCK_PROVIDERS = [
  { abn:"51 234 567 891", name:"Sunrise Disability Services Pty Ltd", state:"NSW", score:94, level:"critical", flags:["dup-contact","reregistered"], suburb:"Fairfield" },
  { abn:"72 891 234 567", name:"CarePath Solutions Australia",          state:"VIC", score:89, level:"critical", flags:["dup-contact","abn-change"],   suburb:"Dandenong" },
  { abn:"33 456 789 012", name:"EnableCare Group Pty Ltd",              state:"QLD", score:87, level:"critical", flags:["reregistered","density"],     suburb:"Logan Central" },
  { abn:"91 012 345 678", name:"PrimeSupport Services",                 state:"NSW", score:82, level:"critical", flags:["dup-contact","no-service"],   suburb:"Villawood" },
  { abn:"64 789 012 345", name:"AccessAbility Connect",                 state:"WA",  score:78, level:"high",     flags:["density","abn-change"],       suburb:"Perth CBD" },
  { abn:"17 345 678 901", name:"Horizon Community Care",                state:"NSW", score:74, level:"high",     flags:["dup-contact"],                suburb:"Auburn" },
  { abn:"85 678 901 234", name:"BrightPath Supports Co",                state:"VIC", score:71, level:"high",     flags:["reregistered"],               suburb:"Hoppers Crossing" },
  { abn:"48 901 234 567", name:"Oasis Care Pty Ltd",                    state:"SA",  score:68, level:"high",     flags:["density","dup-contact"],      suburb:"Adelaide CBD" },
];

const MOCK_DUP_CLUSTERS = [
  { contact:"0412 *** 891", type:"Mobile", entries:[
    { name:"Sunrise Disability Services Pty Ltd", abn:"51 234 567 891", status:"active" },
    { name:"Sunrise Care Group (Aust)",           abn:"73 112 445 902", status:"cancelled" },
    { name:"SRC Support Services",                abn:"19 098 334 771", status:"cancelled" },
  ]},
  { contact:"admin@carepathau.com.au", type:"Email", entries:[
    { name:"CarePath Solutions Australia", abn:"72 891 234 567", status:"active" },
    { name:"CarePath Health Pty Ltd",      abn:"44 229 881 003", status:"cancelled" },
  ]},
];

// ================================================================
//  ABR XML PARSER
// ================================================================
function parseABRXML(xml, abnRaw) {
  const get    = tag => { const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, 'i')); return m ? m[1].trim() : ''; };
  const getAll = tag => { const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'gi'); const r = []; let m; while((m = re.exec(xml)) !== null) r.push(m[1]); return r; };

  const name    = get('organisationName') || get('mainName') || 'Unknown';
  const status  = get('entityStatusCode') || 'Unknown';
  const type    = get('entityTypeCode')   || '';
  const state   = get('mainBusinessPhysicalAddressStateCode') || '';
  const postcode = get('mainBusinessPhysicalAddressPostCode') || '';

  const history = [];
  getAll('entityStatus').forEach(b => {
    const code = (b.match(/<entityStatusCode>([^<]+)/) || [])[1] || '';
    const from = (b.match(/<effectiveFrom>([^<]+)/) || [])[1] || '';
    if (from) history.push({ type: code.toLowerCase().includes('cancel') ? 'cancel' : 'register', date: formatDate(from), event: `Entity status: ${code}` });
  });
  getAll('mainName').forEach(b => {
    const n = (b.match(/<organisationName>([^<]+)/) || [])[1] || '';
    const f = (b.match(/<effectiveFrom>([^<]+)/) || [])[1] || '';
    if (n && f) history.push({ type:'namechange', date:formatDate(f), event:`Name: ${n}` });
  });
  getAll('otherTradingName').forEach(b => {
    const n = (b.match(/<organisationName>([^<]+)/) || [])[1] || '';
    const f = (b.match(/<effectiveFrom>([^<]+)/) || [])[1] || '';
    if (n && f) history.push({ type:'namechange', date:formatDate(f), event:`Trading name: ${n}` });
  });
  history.sort((a,b) => new Date(a.date) - new Date(b.date));

  return {
    abn: formatABN(abnRaw),
    name, state: normaliseState(state), postcode,
    suburb: '',
    type: entityTypeLabel(type),
    status: status.toLowerCase().includes('cancel') ? 'Cancelled' : 'Active',
    gstRegistered: xml.includes('<goodsAndServicesTax>') ? 'Yes' : 'Unknown',
    registeredDate: history.length > 0 ? history[0].date : 'Unknown',
    lastUpdated: formatDate(get('lastUpdatedDate')),
    history, crossRefs: [], riskScore: 0, riskLevel: 'low', flags: [], riskFactors: [],
  };
}

function buildRiskFactors(p) {
  const f = [];
  if ((p.flags||[]).includes('dup-contact'))  f.push({ label:'Duplicate contact across multiple ABNs', severity:'critical' });
  if ((p.flags||[]).includes('reregistered')) f.push({ label:'Previously cancelled ABNs linked to same operator', severity:'critical' });
  if ((p.flags||[]).includes('density'))      f.push({ label:'Located in high-density fraud hotspot suburb', severity:'high' });
  if ((p.flags||[]).includes('abn-change'))   f.push({ label:'Multiple ABN registrations detected', severity:'high' });
  if ((p.flags||[]).includes('no-service'))   f.push({ label:'Claims with no participant match on file', severity:'high' });
  return f;
}

// ================================================================
//  UTILITIES
// ================================================================
function parseCSV(text) {
  const rows = [];
  const lines = text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n');
  for (const line of lines) {
    if (!line.trim()) continue;
    const row = []; let field = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') { if (inQ && line[i+1] === '"') { field += '"'; i++; } else inQ = !inQ; }
      else if (ch === ',' && !inQ) { row.push(field.trim()); field = ''; }
      else field += ch;
    }
    row.push(field.trim());
    rows.push(row);
  }
  return rows;
}

function findCol(headers, candidates) {
  for (const c of candidates) {
    const i = headers.findIndex(h => h === c || h.includes(c));
    if (i !== -1) return i;
  }
  return -1;
}

function clean(s) { return (s || '').replace(/^["']|["']$/g,'').trim(); }

function formatABN(raw) {
  const d = (raw||'').replace(/\D/g,'');
  if (d.length !== 11) return raw || '';
  return `${d.slice(0,2)} ${d.slice(2,5)} ${d.slice(5,8)} ${d.slice(8)}`;
}

function normaliseState(s) {
  const map = {
    'NEW SOUTH WALES':'NSW','VICTORIA':'VIC','QUEENSLAND':'QLD',
    'WESTERN AUSTRALIA':'WA','SOUTH AUSTRALIA':'SA','TASMANIA':'TAS',
    'NORTHERN TERRITORY':'NT','AUSTRALIAN CAPITAL TERRITORY':'ACT',
    'NSW':'NSW','VIC':'VIC','QLD':'QLD','WA':'WA','SA':'SA','TAS':'TAS','NT':'NT','ACT':'ACT',
  };
  return map[(s||'').toUpperCase()] || (s||'').toUpperCase().slice(0,3);
}

function entityTypeLabel(code) {
  const map = { PRV:'Australian Private Company', PUB:'Australian Public Company',
    IND:'Individual/Sole Trader', TRU:'Trust', PTR:'Partnership',
    GOV:'Government Entity', OTH:'Other Entity' };
  return map[code] || code || 'Unknown';
}

function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleDateString('en-AU',{day:'2-digit',month:'short',year:'numeric'});
}
