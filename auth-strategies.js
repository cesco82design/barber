const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const db = require('./database');

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Cerca utente esistente
    const existingUser = await db.getSingle(
      'SELECT * FROM users WHERE googleId = $1', 
      [profile.id]
    );
    
    if (existingUser) return done(null, existingUser);
    
    // Crea nuovo utente
    const newUser = await db.query(
      'INSERT INTO users (googleId) VALUES ($1) RETURNING *',
      [profile.id]
    );
    
    done(null, newUser.rows[0]);
  } catch (err) {
    done(err);
  }
}));

// Local Strategy
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const user = await db.findUserByEmail(email);
    if (!user) return done(null, false, { message: 'Email non registrata' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return done(null, false, { message: 'Password errata' });

    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// Serializzazione
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.getSingle('SELECT id, email, isAdmin FROM users WHERE id = $1', [id]);
    done(null, user);
  } catch (err) {
    done(err);
  }
});
