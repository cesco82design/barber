const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('database.sqlite');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    isAdmin BOOLEAN DEFAULT 0
  )`, () => {
    bcrypt.hash('password123', 10)
      .then(hash => {
        const stmt = db.prepare("INSERT INTO users (email, password, isAdmin) VALUES (?, ?, 1)");
        stmt.run("admin@example.com", hash, function(err) {
          if(err) return console.error(err.message);
          console.log("Admin creato con ID:", this.lastID);
          db.close();
        });
        stmt.finalize();
      })
      .catch(err => console.error(err));
  });
});