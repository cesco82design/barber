#!/usr/bin/env node
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const readline = require('readline');

const db = new sqlite3.Database('database.sqlite');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function resetPassword() {
  try {
    // Chiedi i parametri all'utente
    const email = await askQuestion('Inserisci email utente: ');
    const newPassword = await askQuestion('Inserisci nuova password: ');

    // Genera hash della password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Aggiorna il database
    db.run(
      'UPDATE users SET password = ? WHERE email = ?',
      [hashedPassword, email],
      function(err) {
        if (err) {
          console.error('❌ Errore:', err.message);
        } else {
          if (this.changes > 0) {
            console.log('✅ Password aggiornata con successo per:', email);
          } else {
            console.log('⚠️  Nessun utente trovato con email:', email);
          }
        }
        db.close();
      }
    );
  } catch (error) {
    console.error('❌ Errore durante il reset:', error);
    db.close();
  }
}

function askQuestion(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

resetPassword().finally(() => rl.close());