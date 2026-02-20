require('dotenv').config();
const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const axios = require('axios');
const path = require('path');

const app = express();
const port = 3000; // or whatever, proxy from Caddy

// Session middleware (for server-side session)
app.use(session({
  secret: process.env.SESSION_SECRET || 'An0ther-0ne-Bites-the-Dust',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' } // secure: true needs HTTPS
}));

// JWKS client to verify Cognito JWTs (get keys from Cognito)
const client = jwksClient({
  jwksUri: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.USER_POOL_ID}/.well-known/jwks.json`
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login'); // or to Cognito hosted UI login
  }
}

// Cognito config from .env
const COGNITO_DOMAIN = process.env.COGNITO_DOMAIN; // e.g. yourdomain.auth.region.amazoncognito.com
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET; // if you have one; optional for public clients
const REDIRECT_URI = 'https://dev.litexplorers.au/discover/'; // match your app client callback

// Login button/route: redirect to Hosted UI
app.get('/login', (req, res) => {
  const loginUrl = `https://${COGNITO_DOMAIN}/login?client_id=${CLIENT_ID}&response_type=code&scope=openid+email+profile&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
  res.redirect(loginUrl);
});

// Callback: exchange code for tokens
app.get('/discover/', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    // If no code, maybe render a public discover page or redirect to login
    return res.sendFile(path.join(__dirname, 'public', 'discover.html')); // if you have static fallback
  }

  try {
    const tokenResponse = await axios.post(`https://${COGNITO_DOMAIN}/oauth2/token`, new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code,
      redirect_uri: REDIRECT_URI,
      // client_secret: CLIENT_SECRET, // only if your app client has secret
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const { id_token, access_token, refresh_token } = tokenResponse.data;

    // Verify ID token (important!)
    jwt.verify(id_token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
      if (err) throw err;
      req.session.user = decoded; // store decoded claims (email, sub, etc.)
      req.session.id_token = id_token; // or just store tokens if needed
      res.redirect('/member/'); // or wherever after login
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Authentication failed');
  }
});

// Protected route example
app.get('/member', requireAuth, (req, res) => {
  res.send(`Welcome, ${req.session.user.email}! <a href="/logout">Logout</a>`);
});

// Logout (clear session + redirect to Cognito logout)
app.get('/logout', (req, res) => {
  req.session.destroy();
  const logoutUrl = `https://${COGNITO_DOMAIN}/logout?client_id=${CLIENT_ID}&logout_uri=${encodeURIComponent('https://litexplorers.au/')}`;
  res.redirect(logoutUrl);
});

// Serve static files (your current site)
app.use(express.static(path.join(__dirname, 'public'))); // put your HTML/JS/CSS here

app.listen(port, () => console.log(`Express listening on port ${port}`));
