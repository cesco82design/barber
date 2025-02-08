require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const path = require('path');  // Aggiungi con gli altri require
const LocalStrategy = require('passport-local').Strategy;

// Configurazione database
const db = new sqlite3.Database('database.sqlite');

// Creazione tabelle e dati iniziali
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    googleId TEXT UNIQUE,
    password TEXT,
    isAdmin BOOLEAN DEFAULT 0
  )`);

    db.run(`CREATE TABLE IF NOT EXISTS operators (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS services (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      duration INTEGER
    )`);
  

  db.run(`CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    operatorId INTEGER,
    serviceId INTEGER,
    startTime DATETIME,
    endTime DATETIME,
    FOREIGN KEY(userId) REFERENCES users(id),
    FOREIGN KEY(operatorId) REFERENCES operators(id),
    FOREIGN KEY(serviceId) REFERENCES services(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token TEXT NOT NULL,
    expires DATETIME NOT NULL
  )`);
  // Inserimento dati iniziali
  // Sostituisci gli inserimenti iniziali con:
  db.run(`INSERT OR IGNORE INTO operators (name) VALUES 
          ('Andrea'), 
          ('Giuseppe')`);

  db.run(`INSERT OR IGNORE INTO services (name, duration) VALUES 
          ('Taglio barba', 15),
          ('Taglio capelli', 25),
          ('Taglio completo', 40)`);
  
  
});

// Configurazione Passport
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  // Gestione utente Google
  db.get('SELECT * FROM users WHERE googleId = ?', [profile.id], (err, user) => {
    if (err) return done(err);
    if (!user) {
      db.run('INSERT INTO users (googleId) VALUES (?)', [profile.id], function(err) {
        return done(null, { id: this.lastID, googleId: profile.id });
      });
    } else {
      return done(null, user);
    }
  });
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.get('SELECT id, email, isAdmin FROM users WHERE id = ?', [id], (err, user) => {
    done(err, user);
  });
});

// Configurazione app
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

// Middleware di autenticazione
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};
const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isAdmin === 1) {
    return next();
  }
  res.status(403).render('error', { message: 'Accesso riservato agli amministratori' });
};
app.locals.formatDate = (dateString) => {
  const date = new Date(dateString);
  return date.toLocaleString('it-IT', {
    timeZone: 'Europe/Rome',
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};
// Rotte
app.get('/', (req, res) => res.render('home', { user: req.user }));

app.get('/login', (req, res) => res.render('login', { error: null }));
// Modifica la route /login
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.render('login', { error: info.message });

    req.logIn(user, (err) => {
      if (err) return next(err);

      // Redirect condizionale per admin
      if (user.isAdmin) {
        return res.redirect('/admin');
      }
      return res.redirect('/book');
    });
  })(req, res, next);
});
app.set('views', path.join(__dirname, 'views'));  // Aggiungi in cima al file

// Dashboard Admin
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const [appointments, operators] = await Promise.all([
      new Promise((resolve, reject) => {
        db.all(`
          SELECT a.*, u.email, o.name as operator_name, s.name as service_name 
          FROM appointments a
          JOIN users u ON a.userId = u.id
          JOIN operators o ON a.operatorId = o.id
          JOIN services s ON a.serviceId = s.id
          ORDER BY a.startTime DESC
        `, (err, rows) => err ? reject(err) : resolve(rows))
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM operators', (err, rows) => err ? reject(err) : resolve(rows))
      })
    ]);

    res.render('admin', {
      user: req.user,
      appointments,
      operators, // Aggiungi questo
      formatDate: app.locals.formatDate
    });

  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).render('error', { message: 'Errore nel caricamento dei dati' });
  }
});
app.use('/admin', (req, res, next) => {
  if (!res.locals.operators) {
    db.all('SELECT * FROM operators', (err, operators) => {
      res.locals.operators = operators || [];
      next();
    });
  } else {
    next();
  }
});
app.get('/admin/filter', isAdmin, async (req, res) => {
  try {
    const { date, operator } = req.query;
    let query = `
      SELECT a.*, u.email as user_email, o.name as operator_name, s.name as service_name
      FROM appointments a
      JOIN users u ON a.userId = u.id
      JOIN operators o ON a.operatorId = o.id
      JOIN services s ON a.serviceId = s.id
    `;

    const params = [];
    const conditions = [];

    if(date) {
      conditions.push("DATE(a.startTime) = ?");
      params.push(date);
    }

    if(operator) {
      conditions.push("a.operatorId = ?");
      params.push(operator);
    }

    if(conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    query += " ORDER BY a.startTime DESC";

    const appointments = await new Promise((resolve, reject) => {
      db.all(query, params, (err, rows) => {
        if(err) reject(err);
        resolve(rows);
      });
    });

    res.json(appointments);
  } catch (error) {
    res.status(500).json({ error: 'Errore nel filtro' });
  }
});
// Elimina prenotazione
app.post('/admin/delete/:id', isAdmin, (req, res) => {
  db.run('DELETE FROM appointments WHERE id = ?', [req.params.id], (err) => {
    if(err) return res.status(500).send('Errore nella cancellazione');
    res.redirect('/admin');
  });
});
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', 
      [req.body.email, hashedPassword], 
      function(err) {
        if (err) {
          return res.render('register', { 
            error: err.message.includes('UNIQUE') ? 
            'Email già registrata' : 'Errore di registrazione' 
          });
        }
        res.redirect('/login');
    });
  } catch (error) {
    res.render('register', { error: 'Errore durante la registrazione' });
  }
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/book'));
// Password dimenticata - Pagina
app.get('/forgot-password', (req, res) => res.render('forgot-password', { error: null, success: null }));

// Password dimenticata - Invio token
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const crypto = require('crypto');

  try {
    // Verifica se l'email esiste
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!user) {
      return res.render('forgot-password', { 
        error: 'Nessun account associato a questa email',
        success: null
      });
    }

    // Genera token e data di scadenza
    const token = crypto.randomBytes(20).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 ora

    // Salva nel database
    db.run('INSERT INTO password_resets (email, token, expires) VALUES (?, ?, ?)',
      [email, token, expires.toISOString()]);

    // Simulazione invio email (in produzione usa Nodemailer)
    console.log(`Reset password link: http://${req.headers.host}/reset-password/${token}`);

    res.render('forgot-password', {
      success: 'Email di recupero inviata! Controlla la tua casella.',
      error: null
    });

  } catch (error) {
    res.render('forgot-password', { 
      error: 'Errore durante il processo di recupero',
      success: null
    });
  }
});

// Reset password - Pagina
app.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const resetRequest = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM password_resets WHERE token = ? AND expires > ?',
        [token, new Date().toISOString()],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        });
    });

    if (!resetRequest) {
      return res.render('reset-password', {
        error: 'Token non valido o scaduto',
        token: null
      });
    }

    res.render('reset-password', { 
      error: null,
      token: token
    });

  } catch (error) {
    res.render('reset-password', {
      error: 'Errore durante la verifica del token',
      token: null
    });
  }
});

// Reset password - Conferma
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const resetRequest = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM password_resets WHERE token = ? AND expires > ?',
        [token, new Date().toISOString()],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        });
    });

    if (!resetRequest) {
      return res.render('reset-password', {
        error: 'Token non valido o scaduto',
        token: null
      });
    }

    // Aggiorna password
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('UPDATE users SET password = ? WHERE email = ?',
      [hashedPassword, resetRequest.email]);

    // Elimina token usato
    db.run('DELETE FROM password_resets WHERE token = ?', [token]);

    res.render('login', { 
      error: null,
      success: 'Password aggiornata con successo!'
    });

  } catch (error) {
    res.render('reset-password', {
      error: 'Errore durante il reset della password',
      token: token
    });
  }
});
app.get('/api/operators', isAdmin, (req, res) => {
  db.all('SELECT * FROM operators', (err, rows) => {
    if(err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});
app.get('/book', isAuthenticated, async (req, res) => {
  console.log('User isAdmin status:', req.user.isAdmin);
  try {
    const [services, operators] = await Promise.all([getServices(), getOperators()]);
    res.render('book', { 
      user: req.user,
      services,
      operators,
      // Aggiungi se necessario
      formatDate: app.locals.formatDate 
    });
  } catch (error) {
    res.redirect('/');
  }
});

app.post('/book', isAuthenticated, async (req, res) => {
  const { operatorId, serviceId, dateTime } = req.body;
  const service = await getService(serviceId);
  startTime.setMinutes(startTime.getMinutes() - startTime.getTimezoneOffset());
  const endTime = new Date(startTime.getTime() + service.duration * 60000);

  db.run(`INSERT INTO appointments (userId, operatorId, serviceId, startTime, endTime)
          VALUES (?, ?, ?, ?, ?)`,
          [req.user.id, operatorId, serviceId, startTime.toISOString(), endTime.toISOString()],
          (err) => err ? res.redirect('/book') : res.redirect('/success'));
});

// Modifica la route /success
app.get('/success', isAuthenticated, async (req, res) => {
  try {
    const lastAppointment = await new Promise((resolve, reject) => {
      db.get(`
        SELECT a.*, o.name as operatorName, s.name as serviceName 
        FROM appointments a
        JOIN operators o ON a.operatorId = o.id
        JOIN services s ON a.serviceId = s.id
        WHERE a.userId = ?
        ORDER BY a.id DESC
        LIMIT 1
      `, [req.user.id], (err, row) => {
        if(err) reject(err);
        resolve(row);
      });
    });

    res.render('success', { 
      user: req.user,
      appointment: lastAppointment 
    });
  } catch (error) {
    res.redirect('/book');
  }
});
app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

// API
app.get('/api/available-slots', async (req, res) => {
  const { operatorId, date, serviceId } = req.query;
  try {
    const service = await getService(serviceId);
    const slots = await calculateAvailableSlots(operatorId, new Date(date), service.duration);
    res.json(slots);
  } catch (error) {
    res.status(400).json({ error: 'Dati non validi' });
  }
});

// Funzioni helper e database
async function calculateAvailableSlots(operatorId, date, duration) {
  const appointments = await getAppointments(operatorId, date);
  const slots = [];
  let currentTime = new Date(date);
  currentTime.setHours(8, 30, 0);

  while (true) {
    const endTime = new Date(currentTime.getTime() + duration * 60000);
    if (endTime.getHours() >= 19 || (endTime.getHours() === 19 && endTime.getMinutes() > 0)) break;

    const isAvailable = appointments.every(app => {
      const appStart = new Date(app.startTime);
      const appEnd = new Date(app.endTime);
      return endTime <= appStart || currentTime >= appEnd;
    });

    if (isAvailable) slots.push(currentTime.toISOString());
    currentTime = new Date(currentTime.getTime() + 15 * 60000);
  }

  return slots;
}

// Funzioni database
const getServices = () => new Promise((resolve, reject) => {
  db.all('SELECT * FROM services', (err, rows) => err ? reject(err) : resolve(rows));
});

const getOperators = () => new Promise((resolve, reject) => {
  db.all('SELECT * FROM operators', (err, rows) => err ? reject(err) : resolve(rows));
});

const getService = (id) => new Promise((resolve, reject) => {
  db.get('SELECT * FROM services WHERE id = ?', [id], (err, row) => err ? reject(err) : resolve(row));
});

const getAppointments = (operatorId, date) => new Promise((resolve, reject) => {
  const startDate = new Date(date);
  startDate.setHours(0,0,0,0);
  const endDate = new Date(date);
  endDate.setHours(23,59,59,999);

  db.all(`SELECT * FROM appointments 
         WHERE operatorId = ? 
         AND startTime BETWEEN ? AND ?`,
         [operatorId, startDate.toISOString(), endDate.toISOString()],
         (err, rows) => err ? reject(err) : resolve(rows));
});
// Configura la strategia locale DOPO Google Strategy
passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password'
  },
  async (email, password, done) => {
    try {
      const user = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
          if (err) reject(err);
          resolve(row);
        });
      });

      if (!user) return done(null, false, { message: 'Email non registrata' });

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) return done(null, false, { message: 'Password errata' });

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

app.listen(3000, () => console.log('Server avviato su porta 3000'));