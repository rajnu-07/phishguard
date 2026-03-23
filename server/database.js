const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'phishguard.db');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');

        // Create history table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL,
      status TEXT NOT NULL,
      confidence INTEGER NOT NULL,
      reasons TEXT,
      checkedAt TEXT NOT NULL
    )`, (err) => {
            if (err) {
                console.error('Error creating table', err.message);
            }
        });
    }
});

module.exports = db;
