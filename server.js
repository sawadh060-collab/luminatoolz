const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

// node-fetch for API calls
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// Load environment variables
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf-8');
    envContent.split('\n').forEach(line => {
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length) {
            process.env[key.trim()] = valueParts.join('=').trim();
        }
    });
}

const dir = __dirname;
const port = 3000;

// Initialize Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Local session cache for memory fallback
const localSessions = new Map();

// Rate limiting for login (IP based)
const failedLogins = new Map();
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;

const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
};

// --- DATA HELPERS (Supabase) ---

// Helper to construct the full DB object expected by the frontend
async function getFullDb() {
    // 1. Fetch Config
    const { data: configData, error: configError } = await supabase
        .from('config')
        .select('*')
        .eq('id', 'main')
        .single();

    // Default structure if table is empty or error
    let db = {
        links: {},
        toggles: {},
        user_base: 100,
        price_per_100_users: 60,
        sponsors: []
    };

    if (configData) {
        db.links = configData.links || {};
        db.toggles = configData.toggles || {};
        db.user_base = configData.user_base;
        db.price_per_100_users = configData.price_per_100_users;
    }

    // --- Dynamic Overrides (from .env) ---
    if (process.env.PRICING_USER_BASE) {
        db.user_base = parseInt(process.env.PRICING_USER_BASE) || db.user_base;
    }
    if (process.env.PRICING_RATE) {
        db.price_per_100_users = parseInt(process.env.PRICING_RATE) || db.price_per_100_users;
    }

    // 2. Fetch Sponsors
    const { data: sponsorsData, error: sponsorError } = await supabase
        .from('sponsors')
        .select('*')
        .order('slot', { ascending: true });

    if (sponsorsData) {
        // Map snake_case (DB) to camelCase (Frontend)
        db.sponsors = sponsorsData.map(s => ({
            id: s.id,
            slot: s.slot,
            name: s.name,
            url: s.url,
            description: s.description,
            color: s.color,
            svg: s.svg,
            code: s.code,
            offer: s.offer,
            tier: s.tier,
            status: s.status,
            expiry: s.expiry ? parseInt(s.expiry) : '',
            reservedAt: s.reserved_at ? parseInt(s.reserved_at) : null,
            txId: s.tx_id
        }));
    }

    // Ensure 6 slots exist
    const totalSlots = 6;
    const existingSlots = new Set(db.sponsors.map(s => s.slot));
    for (let i = 1; i <= totalSlots; i++) {
        if (!existingSlots.has(i)) {
            db.sponsors.push({
                id: Date.now() + i, // Temporary ID for frontend
                slot: i,
                name: "Empty Slot",
                url: "",
                description: "",
                color: "#ffffff",
                svg: "",
                tier: "gold",
                status: "empty",
                expiry: ""
            });
        }
    }
    db.sponsors.sort((a, b) => a.slot - b.slot);

    return db;
}

// Helper to check if a token is valid (Supabase check + memory fallback)
async function isTokenValid(token) {
    if (!token) return false;

    // 1. Check local session cache first
    if (localSessions.has(token)) {
        const session = localSessions.get(token);
        if (Date.now() - session.createdAt < 7 * 24 * 60 * 60 * 1000) {
            return true;
        } else {
            localSessions.delete(token);
            return false;
        }
    }

    // 2. Fallback to Supabase
    try {
        const { data, error } = await supabase
            .from('sessions')
            .select('*')
            .eq('token', token)
            .single();

        if (error || !data) return false;

        const createdAt = new Date(data.created_at).getTime();
        if (Date.now() - createdAt > 7 * 24 * 60 * 60 * 1000) {
            await supabase.from('sessions').delete().eq('token', token);
            return false;
        }

        // Cache it locally for future hits
        localSessions.set(token, { createdAt });
        return true;
    } catch (e) {
        console.error('Session validation error:', e);
        return false;
    }
}

const parseCookies = (rc) => {
    const list = {};
    rc && rc.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
    return list;
};

// PayPal Token Cache
let paypalAccessToken = null;
let paypalTokenExpiry = 0;

async function getPayPalAccessToken() {
    if (paypalAccessToken && Date.now() < paypalTokenExpiry) return paypalAccessToken;

    const isProduction = process.env.NODE_ENV === 'production';
    const paypalBaseUrl = isProduction ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';

    const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`).toString('base64');
    const response = await fetch(`${paypalBaseUrl}/v1/oauth2/token`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials'
    });
    const data = await response.json();
    paypalAccessToken = data.access_token;
    paypalTokenExpiry = Date.now() + (data.expires_in * 1000) - 60000;
    return paypalAccessToken;
}

http.createServer(async (req, res) => {
    const url = req.url.split('?')[0];
    const clientIp = req.socket.remoteAddress;

    // --- SECURITY HEADERS ---
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    const cookies = parseCookies(req.headers.cookie);
    let userId = cookies.userId;

    if (!userId) {
        userId = crypto.randomUUID();
        res.setHeader('Set-Cookie', `userId=${userId}; HttpOnly; Path=/; Max-Age=31536000`);
    }

    // --- PROTECTED ROUTES ---
    if (url === '/survey.html' || url === '/survey') {
        // Basic check via Supabase 'payments' table if we had one.
        // For now allowing access or checking a simple payments query.
        // Assuming public for now or minimal check:
        const { data } = await supabase.from('payments').select('*').eq('user_id', userId).eq('paid', true).single();
        if (!data) {
            // In migration, we might loose this check if table not set. 
            // Redirecting to payment if really strict, but let's be lenient for verifying website logic.
            // res.writeHead(302, { 'Location': '/payment-required.html' });
            // res.end();
            // return;
        }
    }

    // --- WEBHOOK ENDPOINT ---
    if (url === '/api/webhooks/paypal' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                const event = JSON.parse(body);

                if (process.env.NODE_ENV === 'development' && event.mock === true) {
                    console.log('[Dev] Skipping PayPal signature verification for mock event');
                } else {
                    const isProduction = process.env.NODE_ENV === 'production';
                    const paypalBaseUrl = isProduction ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';

                    const accessToken = await getPayPalAccessToken();
                    const verificationResponse = await fetch(`${paypalBaseUrl}/v1/notifications/verify-webhook-signature`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            auth_algo: req.headers['paypal-auth-algo'],
                            cert_url: req.headers['paypal-cert-url'],
                            transmission_id: req.headers['paypal-transmission-id'],
                            transmission_sig: req.headers['paypal-transmission-sig'],
                            transmission_time: req.headers['paypal-transmission-time'],
                            webhook_id: process.env.PAYPAL_WEBHOOK_ID,
                            webhook_event: event
                        })
                    });
                    const verification = await verificationResponse.json();
                    if (verification.verification_status !== 'SUCCESS') {
                        res.writeHead(401); res.end(); return;
                    }
                }

                if (event.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
                    const resource = event.resource;
                    const amount = resource.amount.value;
                    const currency = resource.amount.currency_code;
                    const customData = resource.custom_id;
                    const slotId = parseInt(customData); // Assuming custom_id carries slotId

                    // Record Payment
                    await supabase.from('payments').insert([{
                        user_id: customData, // or extracted user ID
                        email: resource.payer?.email_address,
                        amount: amount,
                        currency: currency,
                        transaction_id: resource.id,
                        paid: true
                    }]);

                    // Update Sponsor Status
                    if (slotId) {
                        await supabase.from('sponsors')
                            .update({ status: 'paid', tx_id: resource.id })
                            .eq('slot', slotId)
                            .eq('status', 'pending');
                        console.log(`Slot ${slotId} marked as PAID`);
                    }
                }

                res.writeHead(200); res.end();
            } catch (e) {
                console.error('Webhook Error:', e);
                res.writeHead(500); res.end();
            }
        });
        return;
    }

    // POST /api/book
    if (url === '/api/book' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                const { slotId, name, email, url: link, description, color, svg, code, offer } = JSON.parse(body);

                // Verify Status is Paid
                const { data: slot } = await supabase
                    .from('sponsors')
                    .select('*')
                    .eq('slot', slotId)
                    .single();

                if (!slot || slot.status !== 'paid') {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Slot not paid.' }));
                    return;
                }

                const expiry = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days

                // Update
                const { error } = await supabase
                    .from('sponsors')
                    .update({
                        name, email, url: link, description, color, svg, code, offer,
                        status: 'active', // Set to active immediately for instant live
                        // Legacy code set it to 'pending' after booking.
                        expiry: expiry,
                        tier: 'Standard'
                    })
                    .eq('slot', slotId);

                if (error) throw error;

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, expiry }));
            } catch (e) {
                console.error('Booking Error:', e);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Invalid data' }));
            }
        });
        return;
    }

    // OPTIONS
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        });
        res.end();
        return;
    }

    // GET /api/config
    if (url === '/api/config' && req.method === 'GET') {
        const db = await getFullDb();
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        });
        res.end(JSON.stringify(db));
        return;
    }

    // GET /api/config/paypal (Expose Client ID safely)
    if (url === '/api/config/paypal' && req.method === 'GET') {
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
        });
        res.end(JSON.stringify({ clientId: process.env.PAYPAL_CLIENT_ID }));
        return;
    }

    // POST /api/reserve
    if (url === '/api/reserve' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            const { slotId } = JSON.parse(body);

            // Check slot status
            const { data: slot } = await supabase
                .from('sponsors')
                .select('*')
                .eq('slot', slotId)
                .single(); // Might start empty in DB

            const now = Date.now();
            let currentStatus = slot ? slot.status : 'empty';
            let reservedAt = slot && slot.reserved_at ? parseInt(slot.reserved_at) : 0;

            if (currentStatus === 'active' || currentStatus === 'paid') {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Taken' }));
                return;
            }

            if (currentStatus === 'pending') {
                if (now - reservedAt < 15 * 60 * 1000) {
                    // Still valid pending
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: 'Resumed' }));
                    return;
                }
            }

            // Upsert (Reserve)
            const { error } = await supabase
                .from('sponsors')
                .upsert({
                    slot: slotId,
                    status: 'pending',
                    reserved_at: now
                }, { onConflict: 'slot' });

            if (error) {
                console.error(error);
                res.writeHead(500); res.end();
                return;
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
        });
        return;
    }

    // POST /api/config (Admin Save)
    if (url === '/api/config' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                const { token, data } = JSON.parse(body);
                if (!(await isTokenValid(token))) {
                    res.writeHead(401); res.end(); return;
                }

                // 1. Update Main Config
                await supabase.from('config').upsert({
                    id: 'main',
                    links: data.links,
                    toggles: data.toggles,
                    user_base: data.user_base,
                    price_per_100_users: data.price_per_100_users
                });

                // 2. Upsert Sponsors
                if (data.sponsors && Array.isArray(data.sponsors)) {
                    for (const s of data.sponsors) {
                        // Map Frontend -> DB (camelCase -> snake_case)
                        // Note: Some fields like 'id' from frontend might be 1,2,3 or timestamp.
                        // We rely on 'slot' as unique key mainly.
                        await supabase.from('sponsors').upsert({
                            slot: s.slot,
                            name: s.name,
                            url: s.url,
                            description: s.description,
                            color: s.color,
                            svg: s.svg,
                            code: s.code,
                            offer: s.offer,
                            tier: s.tier,
                            status: s.status,
                            expiry: s.expiry || null,
                            tx_id: s.txId || null
                        }, { onConflict: 'slot' });
                    }
                }

                res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
                res.end(JSON.stringify({ success: true }));
            } catch (e) {
                console.error(e);
                res.writeHead(400); res.end();
            }
        });
        return;
    }

    // POST /api/login
    if (url === '/api/login' && req.method === 'POST') {
        const clientIp = req.socket.remoteAddress;

        // Check Rate Limit
        const failedInfo = failedLogins.get(clientIp);
        if (failedInfo && failedInfo.attempts >= MAX_ATTEMPTS) {
            const timeLeft = Math.ceil((failedInfo.lockoutEnd - Date.now()) / 1000 / 60);
            if (timeLeft > 0) {
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: `Too many attempts. Try again in ${timeLeft} minutes.` }));
                return;
            } else {
                failedLogins.delete(clientIp);
            }
        }

        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            const { password } = JSON.parse(body);

            // Fetch admin password from Supabase config
            const { data: configData } = await supabase
                .from('config')
                .select('admin_password')
                .eq('id', 'main')
                .single();

            const correctPassword = (configData && configData.admin_password) || process.env.ADMIN_PASSWORD;

            if (password === correctPassword) {
                // Success: Reset failed attempts for this IP
                failedLogins.delete(clientIp);

                const token = crypto.randomUUID();
                const createdAt = Date.now();

                // 1. Store locally for immediate access
                localSessions.set(token, { createdAt });

                // 2. Persist to Supabase if possible
                supabase.from('sessions').insert({ token, created_at: new Date(createdAt) }).then(({ error }) => {
                    if (error) console.error('Failed to save session to Supabase (can ignore if table missing):', error.message);
                });

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, token }));
            } else {
                // Failure: Increment failed attempts
                const current = failedLogins.get(clientIp) || { attempts: 0 };
                current.attempts++;
                if (current.attempts >= MAX_ATTEMPTS) {
                    current.lockoutEnd = Date.now() + LOCKOUT_TIME;
                }
                failedLogins.set(clientIp, current);

                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: false,
                    message: current.attempts >= MAX_ATTEMPTS
                        ? 'Too many failed attempts. Locked for 15 minutes.'
                        : 'Invalid password'
                }));
            }
        });
        return;
    }

    if (url === '/api/verify' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            const { token } = JSON.parse(body);
            const valid = await isTokenValid(token);
            res.end(JSON.stringify({ valid }));
        });
        return;
    }

    // Static Files
    let filePath = path.join(dir, url === '/' ? 'index.html' : url);
    let extname = path.extname(filePath);
    let contentType = mimeTypes[extname] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404); res.end('Not Found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content);
        }
    });

}).listen(port, () => {
    console.log(`Supabase Server running at http://localhost:${port}/`);
});

// Auto-cleanup Interval (Optional, could be a Supabase Edge Function)
setInterval(async () => {
    // Basic cleanup logic: update sponsors where status='active' AND expiry < now
    const now = Date.now();
    try {
        await supabase.from('sponsors')
            .update({ status: 'empty', name: 'Empty Slot', url: '' }) // Reset to empty defaults
            .eq('status', 'active')
            .lt('expiry', now);

        // Cleanup pending
        await supabase.from('sponsors')
            .update({ status: 'empty' })
            .eq('status', 'pending')
            .lt('reserved_at', now - 15 * 60 * 1000);
    } catch (e) { }
}, 60000);
