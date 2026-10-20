require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const app = express();

// ---- Session: luu thong tin nguoi dung sau khi dang nhap ----
app.use(session({
  secret: process.env.SESSION_SECRET || 'chi-dung-khi-dev',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 60 * 60 * 1000 } // 1 gio
}));
app.use(passport.initialize());
app.use(passport.session());

// Luu ca object user nho vao session (du cho bai tap, khong can database)
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ---- Cau hinh 2 nha cung cap: chi bat khi co du Client ID + Secret ----
const enabled = { google: false, github: false };

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/google/callback`
  }, (accessToken, refreshToken, profile, done) => {
    done(null, {
      provider: 'google',
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value || null,
      avatar: profile.photos?.[0]?.value || null
    });
  }));
  enabled.google = true;
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/github/callback`,
    scope: ['user:email']
  }, (accessToken, refreshToken, profile, done) => {
    done(null, {
      provider: 'github',
      id: profile.id,
      name: profile.displayName || profile.username,
      email: profile.emails?.[0]?.value || null, // co the null neu email an
      avatar: profile.photos?.[0]?.value || null
    });
  }));
  enabled.github = true;
}

// Neu chua cau hinh nha cung cap thi quay ve trang chu kem thong bao
const needProvider = name => (req, res, next) =>
  enabled[name] ? next() : res.redirect(`/?error=not_configured&provider=${name}`);

const requireLogin = (req, res, next) =>
  req.isAuthenticated() ? next() : res.redirect('/');

// ---- Dang nhap bang Google ----
app.get('/auth/google', needProvider('google'),
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', needProvider('google'),
  passport.authenticate('google', { failureRedirect: '/?error=login_failed' }),
  (req, res) => res.redirect('/profile'));

// ---- Dang nhap bang GitHub ----
app.get('/auth/github', needProvider('github'),
  passport.authenticate('github'));

app.get('/auth/github/callback', needProvider('github'),
  passport.authenticate('github', { failureRedirect: '/?error=login_failed' }),
  (req, res) => res.redirect('/profile'));

// ---- Dang xuat (dung POST de tranh bi dang xuat bang link la) ----
app.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.json({ ok: true });
    });
  });
});

// ---- API nho cho giao dien ----
app.get('/api/providers', (req, res) => res.json(enabled));
app.get('/api/me', (req, res) =>
  req.isAuthenticated() ? res.json(req.user) : res.status(401).json({ error: 'Chua dang nhap' }));

// ---- Trang web ----
app.get('/', (req, res) =>
  req.isAuthenticated()
    ? res.redirect('/profile')
    : res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/profile', requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'profile.html')));

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.listen(PORT, () => {
  console.log(`Chay tai ${BASE_URL}`);
  console.log('Google:', enabled.google ? 'da cau hinh' : 'CHUA cau hinh (thieu GOOGLE_CLIENT_ID/SECRET)');
  console.log('GitHub:', enabled.github ? 'da cau hinh' : 'CHUA cau hinh (thieu GITHUB_CLIENT_ID/SECRET)');
});
