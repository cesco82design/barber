/*require('dotenv').config();
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const path = require('path');
const LocalStrategy = require('passport-local').Strategy;
const PostgreSQLStore = require('connect-pg-simple')(session);
const db = require('./database'); // Importa il modulo database.js

// Configurazione sessione PostgreSQL
app.use(session({
  store: new PostgreSQLStore({
    pool: db.pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 86400000 // 1 giorno
  }
}));

// Configurazione Passport
require('./auth-strategies'); // Importa le strategie di autenticazione

// Configurazione app
app.use(express.static('public'));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());



// Middleware per gestire gli errori
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500);
  res.render('error', { 
    message: err.message || 'Errore interno del server',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// Middleware di autenticazione
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isAdmin) return next();
  res.status(403).render('error', { 
    message: 'Accesso consentito solo agli amministratori' 
  });
};

// Helper per formattazione date
app.locals.formatDate = (dateString) => {
  const options = { 
    year: 'numeric', 
    month: '2-digit', 
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Europe/Rome'
  };
  return new Date(dateString).toLocaleString('it-IT', options);
};

// Rotte principali
app.get('/', (req, res) => res.render('home', { user: req.user }));

// Gestione login
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', passport.authenticate('local', {
  successRedirect: '/book',
  failureRedirect: '/login',
  failureFlash: false
}));

// Gestione registrazione
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await db.createUser(req.body.email, hashedPassword);
    res.redirect('/login');
  } catch (error) {
    res.render('register', { 
      error: error.message.includes('unique') ? 
      'Email già registrata' : 'Errore di registrazione' 
    });
  }
});

// Autenticazione Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/book'));

// Area prenotazioni
app.get('/book', isAuthenticated, async (req, res) => {
  try {
    const [services, operators] = await Promise.all([
      db.getAllServices(),
      db.getAllOperators()
    ]);
    res.render('book', { 
      user: req.user,
      services,
      operators
    });
  } catch (error) {
    res.redirect('/');
  }
});

app.post('/book', isAuthenticated, async (req, res) => {
  try {
    const service = await db.getServiceById(req.body.serviceId);
    const startTime = new Date(req.body.dateTime);
    const endTime = new Date(startTime.getTime() + service.duration * 60000);
    
    await db.createAppointment(
      req.user.id,
      req.body.operatorId,
      req.body.serviceId,
      startTime,
      endTime
    );
    res.redirect('/success');
  } catch (error) {
    res.redirect('/book');
  }
});

// Area admin
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const [appointments, operators] = await Promise.all([
      db.getAllAppointments(),
      db.getAllOperators()
    ]);
    
    res.render('admin', {
      user: req.user,
      appointments,
      operators
    });
  } catch (error) {
    res.status(500).render('error', { message: 'Errore nel caricamento dei dati' });
  }
});

app.post('/admin/delete/:id', isAdmin, async (req, res) => {
  try {
    await db.deleteAppointment(req.params.id);
    res.redirect('/admin');
  } catch (error) {
    res.status(500).send('Errore nella cancellazione');
  }
});

// Gestione password
app.get('/forgot-password', (req, res) => res.render('forgot-password'));
app.post('/forgot-password', async (req, res) => {
  // Implementa la logica di recupero password
});

app.get('/reset-password/:token', async (req, res) => {
  // Implementa la verifica del token
});

app.post('/reset-password/:token', async (req, res) => {
  // Implementa il reset della password
});

// API endpoint
app.get('/api/available-slots', async (req, res) => {
  try {
    const { operatorId, date, serviceId } = req.query;
    const service = await db.getServiceById(serviceId);
    const appointments = await db.getOperatorAppointments(operatorId, date);
    
    const slots = [];
    let currentTime = new Date(date);
    currentTime.setHours(8, 30, 0);

    while (true) {
      const endTime = new Date(currentTime.getTime() + service.duration * 60000);
      if (endTime.getHours() >= 19) break;

      const isAvailable = appointments.every(app => {
        const appStart = new Date(app.startTime);
        const appEnd = new Date(app.endTime);
        return endTime <= appStart || currentTime >= appEnd;
      });

      if (isAvailable) slots.push(currentTime.toISOString());
      currentTime = new Date(currentTime.getTime() + 15 * 60000);
    }

    res.json(slots);
  } catch (error) {
    res.status(400).json({ error: 'Dati non validi' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if(err) return next(err);
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });
});

// Avvio server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server avviato su porta ${PORT}`));*/
require('dotenv').config();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const { pool } = require('./database');
const PostgreSQLStore = require('connect-pg-simple')(session);
const app = express();

// Configurazione sessione
app.use(session({
  store: new PostgreSQLStore({
    pool: pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 86400000
  }
}));

// Inizializzazione database
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE,
        google_id VARCHAR(255) UNIQUE,
        password VARCHAR(255),
        is_admin BOOLEAN DEFAULT FALSE
      );

      CREATE TABLE IF NOT EXISTS operators (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE
      );

      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE,
        duration INTEGER
      );

      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        operator_id INTEGER REFERENCES operators(id),
        service_id INTEGER REFERENCES services(id),
        start_time TIMESTAMP,
        end_time TIMESTAMP
      );

      INSERT INTO operators (name)
      VALUES ('Andrea'), ('Giuseppe')
      ON CONFLICT (name) DO NOTHING;

      INSERT INTO services (name, duration)
      VALUES 
        ('Taglio barba', 15),
        ('Taglio capelli', 25),
        ('Taglio completo', 40)
      ON CONFLICT (name) DO NOTHING;
    `);
    console.log('Database inizializzato correttamente');
  } catch (error) {
    console.error('Errore inizializzazione database:', error);
    process.exit(1);
  }
}

// Configurazione Passport
require('./auth-strategies');

// Configurazione app
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(passport.initialize());
app.use(passport.session());

// Middleware
const isAuthenticated = (req, res, next) => {
  req.isAuthenticated() ? next() : res.redirect('/login');
};

const isAdmin = (req, res, next) => {
  (req.user?.is_admin) ? next() : res.status(403).render('error', { message: 'Accesso non autorizzato' });
};

// Helper
app.locals.formatDate = (dateString) => {
  const options = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Europe/Rome'
  };
  return new Date(dateString).toLocaleString('it-IT', options);
};

// Route
app.get('/', (req, res) => res.render('home', { user: req.user }));

// Autenticazione
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', passport.authenticate('local', {
  successRedirect: '/book',
  failureRedirect: '/login',
  failureFlash: false
}));

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2)',
      [req.body.email, hashedPassword]
    );
    res.redirect('/login');
  } catch (error) {
    res.render('register', {
      error: error.code === '23505' ? 'Email già registrata' : 'Errore di registrazione'
    });
  }
});

// Google OAuth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/book'));

// Prenotazioni
app.get('/book', isAuthenticated, async (req, res) => {
  try {
    const [services, operators] = await Promise.all([
      pool.query('SELECT * FROM services'),
      pool.query('SELECT * FROM operators')
    ]);
    
    res.render('book', {
      user: req.user,
      services: services.rows,
      operators: operators.rows
    });
  } catch (error) {
    res.redirect('/');
  }
});

// Admin
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const [appointments, operators] = await Promise.all([
      pool.query(`
        SELECT a.*, u.email, o.name as operator_name, s.name as service_name 
        FROM appointments a
        JOIN users u ON a.user_id = u.id
        JOIN operators o ON a.operator_id = o.id
        JOIN services s ON a.service_id = s.id
        ORDER BY a.start_time DESC
      `),
      pool.query('SELECT * FROM operators')
    ]);

    res.render('admin', {
      user: req.user,
      appointments: appointments.rows,
      operators: operators.rows
    });
  } catch (error) {
    res.status(500).render('error', { message: 'Errore nel caricamento dei dati' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy();
    res.redirect('/');
  });
});

// Avvio applicazione
const PORT = process.env.PORT || 3000;
initializeDatabase().then(() => {
  app.listen(PORT, () => console.log(`Server attivo su porta ${PORT}`));
});
