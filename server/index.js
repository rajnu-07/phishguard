const express = require('express');
const cors = require('cors');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
// 1. Get all history
app.get('/api/history', (req, res) => {
    db.all('SELECT * FROM history ORDER BY id DESC LIMIT 50', [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        // Parse the reasons array back from JSON string
        const formattedRows = rows.map(row => ({
            ...row,
            reasons: JSON.parse(row.reasons)
        }));
        res.json(formattedRows);
    });
});

// 2. Add to history
app.post('/api/history', (req, res) => {
    const { url, status, confidence, reasons, checkedAt } = req.body;

    if (!url || !status || confidence === undefined) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
    }

    // First, let's remove any existing entry for this URL so it gets added to the top
    db.run('DELETE FROM history WHERE url = ?', [url], (err) => {
        if (err) {
            console.error('Error deleting old entry', err);
            // We continue anyway, not a critical failure
        }

        // Now insert the new entry
        const sql = `INSERT INTO history (url, status, confidence, reasons, checkedAt) 
                 VALUES (?, ?, ?, ?, ?)`;
        const params = [url, status, confidence, JSON.stringify(reasons || []), checkedAt];

        db.run(sql, params, function (err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({
                id: this.lastID,
                url,
                status,
                confidence,
                reasons,
                checkedAt
            });
        });
    });
});

// 3. Clear all history
app.delete('/api/history', (req, res) => {
    db.run('DELETE FROM history', function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ message: 'All history cleared' });
    });
});

// 4. Remove a specific URL from history
app.delete('/api/history/:url', (req, res) => {
    const url = req.params.url;
    // Note: Express treats the rest of the path as the parameter.
    // URL encoded parameters like /api/history/http%3A%2F%2Fexample.com will automatically be decoded.
    db.run('DELETE FROM history WHERE url = ?', [url], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ message: 'URL removed from history', deleted: this.changes });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
