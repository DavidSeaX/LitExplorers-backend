// server.js
const express = require('express');
const cookieSession = require('cookie-session');
const crypto = require('crypto');
const querystring = require('querystring');
const fetch = require('node-fetch'); // npm install node-fetch@2 (for Node <18; or use native fetch in Node 18+)

const app = express();
const port = 3000;

// Load from .env
require('dotenv').config();

const COGNITO_DOMAIN = process.env.COGNITO_DOMAIN;          // e.g. https://myapp.auth.ap-southeast-2.amazoncognito.com
const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
const REDIRECT_URI = process.env.REDIRECT_URI;              // e.g. http://localhost:3000/callback
const REGION = process.env.AWS_REGION || 'ap-southeast-2'; // for token endpoint if needed

// At top of file, after app setup
app.use((req, res, next) => {
  console.log(`Request: ${req.method} ${req.path} | Session:`, req.session);
  next();
});

// Simple session (for verifier + later user info)
app.use(cookieSession({
  name: 'session',
  keys: [process.env.COOKIE_SECRET || 'once-upon-a-time-in-Davids-city'], // change this!
  maxAge: 24 * 60 * 60 * 1000 // 1 day
}));

app.use(express.urlencoded({ extended: true }));

// Helper: Generate random string for code_verifier (43-128 chars, high entropy)
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url'); // ~43 chars
}

// Helper: SHA256 hash → base64url (for code_challenge)
function generateCodeChallenge(verifier) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}

// GET /login - Start PKCE login
app.get('/login', (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Store verifier temporarily in session (encrypted cookie)
  req.session.codeVerifier = codeVerifier;

  // Optional: state for CSRF protection (random value, check on callback)
  const state = crypto.randomBytes(16).toString('hex');
  req.session.state = state;

  const authUrl = `${COGNITO_DOMAIN}/oauth2/authorize?` + querystring.stringify({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email', // adjust scopes
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(authUrl);
});

// GET /callback - Cognito redirects here with ?code=...
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`Login error: ${error} - ${req.query.error_description}`);
  }

  if (!code || !state) {
    return res.status(400).send('Missing code or state');
  }

  // Check state to prevent CSRF
  if (state !== req.session.state) {
    return res.status(400).send('Invalid state parameter (possible CSRF)');
  }

  const codeVerifier = req.session.codeVerifier;
  if (!codeVerifier) {
    return res.status(400).send('No code verifier found - session expired?');
  }

  // Clean up session
  delete req.session.codeVerifier;
  delete req.session.state;

  // Exchange code for tokens (PKCE style - no client_secret!)
  const tokenUrl = `${COGNITO_DOMAIN}/oauth2/token`;
  const body = querystring.stringify({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code: code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier
  });

  try {
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body
    });

    if (!response.ok) {
      const err = await response.json();
      console.error('Token exchange failed:', err);
      return res.status(400).send(`Token exchange failed: ${err.error} - ${err.error_description}`);
    }

    const tokens = await response.json();

    // Store tokens/user info in session (in real app, use secure httpOnly cookies or JWT)
    req.session.tokens = tokens;
    req.session.user = { loggedIn: true }; // placeholder; decode id_token for real user info

    // In /callback, after setting session:
    console.log('Session set in callback:', req.session);

    res.redirect('/profile');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error during token exchange');
  }
});

// Protected route example
app.get('/profile', (req, res) => {
  console.log('Profile accessed, session:', req.session);
  if (!req.session.user?.loggedIn) {
    // Instead of redirect to /login (which restarts flow), redirect to home or show login link
    return res.redirect('/');  // or res.send('Please <a href="/login">log in</a>');
  }
  // Existing welcome code...
  res.send(`
    <h1>Welcome! You are logged in.</h1>
    <p>Access token snippet: ${req.session.tokens?.access_token?.substring(0, 20)}...</p>
    <a href="/logout">Logout</a>
  `);
});

// Logout (simple - clear session; real logout should hit /logout endpoint too)
app.get('/logout', (req, res) => {
  req.session = null;
  res.redirect('/');
});

app.get('/', (req, res) => {
  res.send(`
    <h1>Cognito PKCE Example</h1>
    <a href="/login">Login with Cognito</a>
  `);
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
