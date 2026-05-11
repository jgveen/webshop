require('dotenv').config();
const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Client: SshClient } = require('ssh2');
const fs = require('fs');
const net = require('net');
const multer = require('multer');
const nodemailer = require('nodemailer');
const https = require('https');

// ---- GEOCODING (Nominatim) + HAVERSINE ----
const geocodeCache = new Map();

function geocodePostcode(postcode) {
  const pc = postcode.replace(/\s/g,'').toUpperCase().slice(0,6);
  const key = pc.slice(0,4);
  if (geocodeCache.has(key)) return Promise.resolve(geocodeCache.get(key));
  return new Promise((resolve) => {
    const options = {
      hostname: 'api.pdok.nl',
      path: `/bzk/locatieserver/search/v3_1/free?q=${encodeURIComponent(pc)}&rows=1&fl=centroide_ll`,
      method: 'GET',
      headers: { 'User-Agent': 'Webshop-Bezorgcheck/1.0' }
    };
    const req = https.request(options, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', () => {
        try {
          const json = JSON.parse(data);
          const doc = json.response && json.response.docs && json.response.docs[0];
          if (doc && doc.centroide_ll) {
            // POINT(lon lat)
            const m = doc.centroide_ll.match(/POINT\(([^\s]+)\s+([^\)]+)\)/);
            if (m) {
              const coords = { lat: parseFloat(m[2]), lon: parseFloat(m[1]) };
              geocodeCache.set(key, coords);
              return resolve(coords);
            }
          }
          resolve(null);
        } catch(e) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(5000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function haversineKm(a, b) {
  const R = 6371;
  const dLat = (b.lat - a.lat) * Math.PI / 180;
  const dLon = (b.lon - a.lon) * Math.PI / 180;
  const h = Math.sin(dLat/2)**2 + Math.cos(a.lat*Math.PI/180) * Math.cos(b.lat*Math.PI/180) * Math.sin(dLon/2)**2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

const sliderUpload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'public', 'slider'),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, 'slide_' + Date.now() + ext);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Alleen afbeeldingen toegestaan'));
  },
  limits: { fileSize: 8 * 1024 * 1024 }
});

const werkzaamhedenUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = path.join(__dirname, 'public', 'werkzaamheden');
      require('fs').mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, 'wz_' + Date.now() + '_' + Math.random().toString(36).slice(2,7) + ext);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Alleen afbeeldingen toegestaan'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

const servicesUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = path.join(__dirname, 'public', 'services');
      require('fs').mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, 'svc_' + Date.now() + '_' + Math.random().toString(36).slice(2,7) + ext);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Alleen afbeeldingen toegestaan'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

const groepUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Alleen afbeeldingen toegestaan'));
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});


const productUpload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'public', 'producten'),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, 'prod_' + Date.now() + '_' + Math.random().toString(36).slice(2,7) + ext);
    }
  }),
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Alleen afbeeldingen toegestaan'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

const app = express();

// ---- SECURITY HEADERS ----
app.use(helmet({
  contentSecurityPolicy: false,          // eigen HTML inline scripts
  crossOriginOpenerPolicy: false,        // vereist HTTPS, niet van toepassing op HTTP
  originAgentCluster: false              // vereist consistente toepassing op alle pagina's
}));

// ---- DATABASE ----
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

db.query('SELECT 1', (err) => {
  if (err) {
    console.error('Database verbinding mislukt:', err);
  } else {
    console.log('Verbonden met MariaDB');
  }
});

// ---- RATE LIMITING ----
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuten
  max: 10,                   // max 10 pogingen per IP
  message: { error: 'Te veel inlogpogingen. Probeer het later opnieuw.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '10kb' }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 3600000, sameSite: 'strict' }
}));

// ---- STATISCHE BESTANDEN (alleen /public, NIET /backend) ----
app.use(express.static(path.join(__dirname, 'public')));

// ---- BACKEND HTML ALLEEN VIA BEVEILIGDE ROUTES ----

// Middleware: alleen ingelogde klanten/admins mogen de site zien
function requireKlant(req, res, next) {
  if (req.session && req.session.gebruiker) return next();
  res.redirect('/login.html');
}

// Middleware: alleen medewerkers en admins
function requireMedewerker(req, res, next) {
  if (req.session && req.session.gebruiker &&
      (req.session.gebruiker.rol === 'medewerker' || req.session.gebruiker.rol === 'admin')) {
    return next();
  }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Niet ingelogd' });
  res.redirect('/backend/login.html');
}

// Middleware: alleen admins
function requireAdmin(req, res, next) {
  if (req.session && req.session.gebruiker && req.session.gebruiker.rol === 'admin') {
    return next();
  }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Niet ingelogd' });
  res.redirect('/backend/login.html');
}

// --- API: producten ---
// Admin met includeInactive=1: alle producten zichtbaar; anders: alleen actief=1
app.get('/api/producten', (req, res) => {
  const isAdmin   = req.session && req.session.gebruiker &&
                    (req.session.gebruiker.rol === 'medewerker' || req.session.gebruiker.rol === 'admin');
  // Alleen admin-paneel mag inactieve producten opvragen via includeInactive=1
  const includeInactive = isAdmin && req.query.includeInactive === '1';
  const zoek      = (req.query.q || '').trim();
  const groepId   = req.query.groep_id || null;
  const pagina    = Math.max(1, parseInt(req.query.pagina) || 1);
  const maxPp     = isAdmin ? 5000 : 100;
  const perPagina = Math.min(maxPp, parseInt(req.query.per_pagina) || 50);
  const offset    = (pagina - 1) * perPagina;

  const params = [];
  const wheres = ['p.verwijderd_op IS NULL'];
  if (!includeInactive) {
    // Publieke site én admin zonder expliciete override: alleen actieve producten
    wheres.push('p.actief = 1');
  }
  if (includeInactive && req.query.actief !== undefined) {
    wheres.push('p.actief = ?');
    params.push(parseInt(req.query.actief) ? 1 : 0);
  }
  if (zoek) {
    // Splits op spaties → elk woord moet voorkomen in naam OF artikelcode (AND-logica)
    const woorden = zoek.split(/\s+/).filter(Boolean);
    for (const woord of woorden) {
      wheres.push('(p.naam LIKE ? OR p.artikelcode LIKE ? OR p.beschrijving LIKE ?)');
      params.push(`%${woord}%`, `%${woord}%`, `%${woord}%`);
    }
  }
  if (groepId) {
    wheres.push('p.groep_id = ?');
    params.push(groepId);
  }
  // Bezorgtype filter op publieke site (veilige whitelist)
  if (req.query.bezorging) {
    const bv = req.query.bezorging.trim();
    if (bv === 'afhaal') {
      // Afhalen = geen beperking, alles tonen
    } else if (bv === 'zelf') {
      wheres.push("p.bezorging IN ('zelf', 'post')");
    } else if (bv === 'post') {
      wheres.push("p.bezorging = 'post'");
    }
  }
  const where = wheres.join(' AND ');

  db.query(`SELECT COUNT(*) AS totaal FROM producten p WHERE ${where}`, params, (err, cnt) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    const totaal = cnt[0].totaal;
    db.query(
      `SELECT p.id, p.artikelcode, p.naam, p.beschrijving, p.prijs, p.eenheid,
              p.voorraad_actueel, p.minimum_voorraad, p.magazijnloc, p.barcode, p.gewicht,
              p.groep_id, pg.naam AS groep_naam, p.leverancier_id, lv.naam AS leverancier_naam, p.aangemaakt_op, p.actief, p.bezorging,
              (SELECT bestandsnaam FROM product_afbeeldingen WHERE product_id = p.id ORDER BY volgorde, id LIMIT 1) AS afbeelding
       FROM producten p LEFT JOIN productgroepen pg ON p.groep_id = pg.id LEFT JOIN leveranciers lv ON p.leverancier_id = lv.id
       WHERE ${where} ORDER BY p.naam LIMIT ? OFFSET ?`,
      [...params, perPagina, offset],
      (err2, results) => {
        if (err2) return res.status(500).json({ error: 'Database fout' });
        res.json({ totaal, pagina, per_pagina: perPagina, items: results });
      }
    );
  });
});

// --- API: productgroepen (openbaar, zonder BLOBs) ---
app.get('/api/groepen', (req, res) => {
  const parent = req.query.parent_id;
  let sql, params;
  if (parent === 'null' || parent === '0' || parent === undefined) {
    sql = 'SELECT id, naam, parent_id, level, sort_order FROM productgroepen WHERE verwijderd_op IS NULL AND (parent_id IS NULL OR parent_id = 0) ORDER BY sort_order, naam';
    params = [];
  } else {
    sql = 'SELECT id, naam, parent_id, level, sort_order FROM productgroepen WHERE verwijderd_op IS NULL AND parent_id = ? ORDER BY sort_order, naam';
    params = [parent];
  }
  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    // Voeg toe of elke groep kinderen heeft
    db.query('SELECT DISTINCT parent_id FROM productgroepen WHERE verwijderd_op IS NULL AND parent_id IS NOT NULL', (err2, childRows) => {
      const metKinderen = new Set(childRows ? childRows.map(r => r.parent_id) : []);
      res.json(results.map(g => ({ ...g, heeft_kinderen: metKinderen.has(g.id) })));
    });
  });
});

// --- API: thumbnail afbeelding (openbaar) ---
app.get('/api/groepen/:id/afbeelding', (req, res) => {
  db.query('SELECT image_thumbnail FROM productgroepen WHERE id = ? AND verwijderd_op IS NULL', [req.params.id], (err, results) => {
    if (err || results.length === 0 || !results[0].image_thumbnail) {
      return res.status(404).end();
    }
    const buf = results[0].image_thumbnail;
    // Detecteer formaat op magic bytes
    let contentType = 'image/jpeg';
    if (buf[0] === 0x89 && buf[1] === 0x50) contentType = 'image/png';
    else if (buf[0] === 0x47 && buf[1] === 0x49) contentType = 'image/gif';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.end(buf);
  });
});

// --- API: product afbeeldingen (openbaar, alleen bestandsnamen) ---
app.get('/api/publiek/producten/:id/afbeeldingen', (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Ongeldig ID' });
  db.query(
    'SELECT bestandsnaam FROM product_afbeeldingen WHERE product_id = ? ORDER BY volgorde, id',
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(results);
    }
  );
});

// --- API: publieke crosssales ---
app.get('/api/publiek/producten/:id/crosssales', (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Ongeldig ID' });
  db.query(
    `SELECT p.id, p.naam, p.prijs, p.artikelcode, p.eenheid,
       (SELECT bestandsnaam FROM product_afbeeldingen WHERE product_id = p.id ORDER BY volgorde, id LIMIT 1) AS afbeelding
     FROM product_crosssales cs
     JOIN producten p ON p.id = cs.crosssale_id
     WHERE cs.product_id = ? AND p.actief = 1 AND p.verwijderd_op IS NULL
     ORDER BY cs.volgorde, cs.id`,
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(results);
    }
  );
});

// --- API: admin crosssales beheer ---
app.get('/api/producten/:id/crosssales', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Ongeldig ID' });
  db.query(
    `SELECT cs.id, cs.crosssale_id, cs.volgorde, p.naam, p.artikelcode,
       (SELECT bestandsnaam FROM product_afbeeldingen WHERE product_id = p.id ORDER BY volgorde, id LIMIT 1) AS afbeelding
     FROM product_crosssales cs
     JOIN producten p ON p.id = cs.crosssale_id
     WHERE cs.product_id = ?
     ORDER BY cs.volgorde, cs.id`,
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(results);
    }
  );
});

app.post('/api/producten/:id/crosssales', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const crosssaleId = parseInt(req.body.crosssale_id);
  if (!id || !crosssaleId) return res.status(400).json({ error: 'Ongeldig ID' });
  if (id === crosssaleId) return res.status(400).json({ error: 'Product kan niet zijn eigen crosssale zijn' });
  db.query(
    'INSERT IGNORE INTO product_crosssales (product_id, crosssale_id, volgorde) VALUES (?, ?, (SELECT COALESCE(MAX(volgorde),0)+1 FROM product_crosssales cs2 WHERE cs2.product_id = ?))',
    [id, crosssaleId, id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ success: true });
    }
  );
});

app.delete('/api/producten/:id/crosssales/:csid', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const csid = parseInt(req.params.csid);
  if (!id || !csid) return res.status(400).json({ error: 'Ongeldig ID' });
  db.query(
    'DELETE FROM product_crosssales WHERE crosssale_id = ? AND product_id = ?',
    [csid, id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ success: true });
    }
  );
});

// --- API: prullenbak producten (vóór :id route!) ---
app.get('/api/producten/prullenbak', requireMedewerker, (req, res) => {
  db.query(`SELECT p.*, pg.naam AS groep_naam FROM producten p LEFT JOIN productgroepen pg ON p.groep_id = pg.id WHERE p.verwijderd_op IS NOT NULL ORDER BY p.verwijderd_op DESC`, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(results);
  });
});

app.post('/api/producten/herstel/:id', requireMedewerker, (req, res) => {
  db.query('UPDATE producten SET verwijderd_op = NULL WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

app.delete('/api/producten/permanent/:id', requireMedewerker, (req, res) => {
  db.query('DELETE FROM producten WHERE id = ? AND verwijderd_op IS NOT NULL', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

// --- API: barcode/artikelcode scan (exacte match) ---
app.get('/api/producten/scan', requireMedewerker, (req, res) => {
  const code = (req.query.code || '').trim();
  if (!code) return res.status(400).json({ error: 'Code verplicht' });
  db.query(
    `SELECT p.id, p.artikelcode, p.naam, p.prijs, p.eenheid, p.barcode,
       (SELECT bestandsnaam FROM product_afbeeldingen WHERE product_id = p.id ORDER BY volgorde, id LIMIT 1) AS afbeelding
     FROM producten p
     WHERE p.verwijderd_op IS NULL AND (TRIM(TRAILING '.' FROM TRIM(TRAILING '0' FROM p.barcode)) = ? OR p.barcode = ? OR p.artikelcode = ?)
     LIMIT 1`,
    [code, code, code],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      if (results.length === 0) return res.status(404).json({ error: 'Niet gevonden' });
      res.json(results[0]);
    }
  );
});

// --- API: enkel product (alleen medewerkers/admin) ---
app.get('/api/producten/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Ongeldig ID' });
  db.query(
    `SELECT p.*, pg.naam AS groep_naam FROM producten p LEFT JOIN productgroepen pg ON p.groep_id = pg.id WHERE p.id = ? AND p.verwijderd_op IS NULL`,
    [id], (err, results) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      if (results.length === 0) return res.status(404).json({ error: 'Niet gevonden' });
      res.json(results[0]);
    }
  );
});

// --- Login ---
app.post('/api/login', loginLimiter, (req, res) => {
  const { email, wachtwoord } = req.body;
  if (!email || !wachtwoord || typeof email !== 'string' || typeof wachtwoord !== 'string') {
    return res.status(400).json({ error: 'E-mail en wachtwoord zijn verplicht.' });
  }
  if (wachtwoord.length > 128) {
    return res.status(400).json({ error: 'Ongeldig e-mail of wachtwoord' });
  }
  db.query('SELECT * FROM gebruikers WHERE email = ? AND verwijderd_op IS NULL', [email.trim()], (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: 'Ongeldig e-mail of wachtwoord' });
    const gebruiker = results[0];
    if (!bcrypt.compareSync(wachtwoord, gebruiker.wachtwoord)) {
      return res.status(401).json({ error: 'Ongeldig e-mail of wachtwoord' });
    }
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Sessie fout' });
      req.session.gebruiker = { id: gebruiker.id, naam: gebruiker.voornaam, email: gebruiker.email, rol: gebruiker.rol };
      if (req.body.onthouMe === true) {
        req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 dagen
      }
      if (gebruiker.rol === 'klant') {
        res.json({ redirect: '/profiel.html' });
      } else if (gebruiker.rol === 'admin') {
        res.json({ redirect: '/backend/admin.html' });
      } else {
        res.json({ redirect: '/backend/dashboard.html' });
      }
    });
  });
});

// --- Registreren (openbaar, alleen klant-rol) ---
app.post('/api/registreren', loginLimiter, (req, res) => {
  const { voornaam, achternaam, email, wachtwoord } = req.body;
  if (!voornaam || !email || !wachtwoord || typeof wachtwoord !== 'string') {
    return res.status(400).json({ error: 'Vul alle verplichte velden in.' });
  }
  if (wachtwoord.length < 8) return res.status(400).json({ error: 'Wachtwoord moet minimaal 8 tekens zijn.' });
  if (wachtwoord.length > 128) return res.status(400).json({ error: 'Wachtwoord te lang.' });
  const hash = require('bcryptjs').hashSync(wachtwoord, 12);
  db.query(
    'INSERT INTO gebruikers (voornaam, achternaam, email, wachtwoord, rol) VALUES (?, ?, ?, ?, ?)',
    [voornaam.trim(), (achternaam || '').trim(), email.trim().toLowerCase(), hash, 'klant'],
    (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Dit e-mailadres is al in gebruik.' });
        return res.status(500).json({ error: 'Database fout.' });
      }
      res.json({ success: true });
    }
  );
});

// --- Klant: eigen profiel ophalen ---
app.get('/api/profiel', requireKlant, (req, res) => {
  db.query(
    'SELECT id, voornaam, achternaam, adres, huisnummer, postcode, woonplaats, telefoon, email, rol, aangemaakt_op FROM gebruikers WHERE id = ? AND verwijderd_op IS NULL',
    [req.session.gebruiker.id],
    (err, results) => {
      if (err || results.length === 0) return res.status(404).json({ error: 'Niet gevonden' });
      res.json(results[0]);
    }
  );
});

// --- Klant: eigen profiel bijwerken ---
app.put('/api/profiel', requireKlant, (req, res) => {
  const { voornaam, achternaam, adres, huisnummer, postcode, woonplaats, telefoon } = req.body;
  if (!voornaam || typeof voornaam !== 'string') return res.status(400).json({ error: 'Voornaam is verplicht.' });
  db.query(
    'UPDATE gebruikers SET voornaam=?, achternaam=?, adres=?, huisnummer=?, postcode=?, woonplaats=?, telefoon=? WHERE id=? AND verwijderd_op IS NULL',
    [voornaam.trim(), (achternaam || '').trim(), adres || null, huisnummer || null, postcode || null, woonplaats || null, telefoon || null, req.session.gebruiker.id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database fout.' });
      req.session.gebruiker.naam = voornaam.trim();
      res.json({ success: true });
    }
  );
});

// --- Klant: wachtwoord wijzigen ---
app.put('/api/profiel/wachtwoord', requireKlant, (req, res) => {
  const { huidig, nieuw } = req.body;
  if (!huidig || !nieuw || typeof nieuw !== 'string' || nieuw.length < 8) {
    return res.status(400).json({ error: 'Nieuw wachtwoord moet minimaal 8 tekens zijn.' });
  }
  if (nieuw.length > 128) return res.status(400).json({ error: 'Wachtwoord te lang.' });
  db.query('SELECT wachtwoord FROM gebruikers WHERE id = ? AND verwijderd_op IS NULL', [req.session.gebruiker.id], (err, results) => {
    if (err || results.length === 0) return res.status(500).json({ error: 'Fout' });
    if (!bcrypt.compareSync(huidig, results[0].wachtwoord)) {
      return res.status(401).json({ error: 'Huidig wachtwoord klopt niet.' });
    }
    const hash = bcrypt.hashSync(nieuw, 12);
    db.query('UPDATE gebruikers SET wachtwoord=? WHERE id=?', [hash, req.session.gebruiker.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'Database fout.' });
      res.json({ success: true });
    });
  });
});

// --- Uitloggen ---
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ redirect: '/login.html' });
});

// --- Sessie info ---
app.get('/api/sessie', (req, res) => {
  if (req.session && req.session.gebruiker) {
    res.json(req.session.gebruiker);
  } else {
    res.status(401).json({ error: 'Niet ingelogd' });
  }
});

// --- Backend: login pagina ---
app.get('/backend/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'backend', 'login.html'));
});

// --- Publiek: login / registreren pagina ---
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/registreren.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registreren.html'));
});
app.get('/profiel.html', requireKlant, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profiel.html'));
});

// --- Backend: medewerker dashboard ---
app.get('/backend/dashboard.html', requireMedewerker, (req, res) => {
  res.sendFile(path.join(__dirname, 'backend', 'dashboard.html'));
});

// --- Backend: admin pagina ---
app.get('/backend/admin.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'backend', 'admin.html'));
});

// ---- KASSA ----
app.get('/kassa', requireMedewerker, (req, res) => {
  res.sendFile(path.join(__dirname, 'backend', 'kassa.html'));
});

app.post('/api/kassa/verkoop', requireMedewerker, (req, res) => {
  const { betaalmethode, totaal, regels, bezorgwijze, klant_id } = req.body;
  if (!regels || !regels.length) return res.status(400).json({ error: 'Geen regels' });
  const methode = ['pin','cash','rekening'].includes(betaalmethode) ? betaalmethode : 'pin';
  const bezorg = ['afhaal','bezorging'].includes(bezorgwijze) ? bezorgwijze : 'afhaal';
  if (methode === 'rekening' && !klant_id) return res.status(400).json({ error: 'Klant verplicht voor op rekening' });
  db.query('INSERT INTO kassa_verkopen (betaalmethode, totaal, bezorgwijze, klant_id) VALUES (?,?,?,?)',
    [methode, parseFloat(totaal) || 0, bezorg, klant_id || null],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      const verkoop_id = result.insertId;
      const rows = regels.map(r => [verkoop_id, r.product_id || null, r.naam, parseFloat(r.aantal), parseFloat(r.prijs_per_stuk)]);
      db.query('INSERT INTO kassa_verkoop_regels (verkoop_id, product_id, naam, aantal, prijs_per_stuk) VALUES ?',
        [rows],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'DB fout regels' });
          res.json({ id: verkoop_id });
        });
    });
});

// Klanten zoeken voor kassa klant-selectie
app.get('/api/kassa/klanten', requireMedewerker, (req, res) => {
  const q = (req.query.q || '').trim();
  if (q) {
    const like = '%' + q + '%';
    db.query(
      `SELECT id, voornaam, achternaam, email, telefoon, postcode, woonplaats, kortingsklant
       FROM gebruikers WHERE verwijderd_op IS NULL AND rol = 'klant'
       AND (voornaam LIKE ? OR achternaam LIKE ? OR email LIKE ? OR telefoon LIKE ? OR postcode LIKE ? OR woonplaats LIKE ?)
       ORDER BY voornaam, achternaam LIMIT 50`,
      [like, like, like, like, like, like],
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB fout' });
        res.json(rows);
      }
    );
  } else {
    db.query(
      `SELECT id, voornaam, achternaam, email, telefoon, postcode, woonplaats, kortingsklant
       FROM gebruikers WHERE verwijderd_op IS NULL AND rol = 'klant'
       ORDER BY aangemaakt_op DESC LIMIT 20`,
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB fout' });
        res.json(rows);
      }
    );
  }
});

// Dag overzicht: alle transacties vandaag die nog niet afgesloten zijn
app.get('/api/kassa/dag-overzicht', requireMedewerker, (req, res) => {
  db.query(`
    SELECT kv.id, kv.betaalmethode, kv.totaal, kv.aangemaakt_op, kv.bezorgwijze, kv.klant_id,
           TRIM(CONCAT_WS(' ', g.voornaam, g.achternaam)) AS klant_naam,
           GROUP_CONCAT(CONCAT(kvr.naam, ' x', kvr.aantal) ORDER BY kvr.id SEPARATOR ', ') AS regels_samenvatting
    FROM kassa_verkopen kv
    LEFT JOIN kassa_verkoop_regels kvr ON kvr.verkoop_id = kv.id
    LEFT JOIN gebruikers g ON g.id = kv.klant_id
    WHERE DATE(kv.aangemaakt_op) = CURDATE()
    GROUP BY kv.id
    ORDER BY kv.aangemaakt_op DESC`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      // Check of vandaag al afgesloten is
      db.query('SELECT id FROM kassa_dag_afsluitingen WHERE datum = CURDATE()', (err2, afgRows) => {
        if (err2) return res.status(500).json({ error: 'DB fout' });
        const afgesloten = afgRows.length > 0;
        const totaal_pin = rows.filter(r => r.betaalmethode === 'pin').reduce((s, r) => s + parseFloat(r.totaal), 0);
        const totaal_cash = rows.filter(r => r.betaalmethode === 'cash').reduce((s, r) => s + parseFloat(r.totaal), 0);
        res.json({ afgesloten, transacties: rows, totaal_pin, totaal_cash, totaal: totaal_pin + totaal_cash });
      });
    });
});

// Enkel transactie detail (regels)
app.get('/api/kassa/verkopen/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Ongeldig id' });
  db.query(
    `SELECT kv.id, kv.betaalmethode, kv.totaal, kv.aangemaakt_op, kv.bezorgwijze, kv.klant_id,
            TRIM(CONCAT_WS(' ', g.voornaam, g.achternaam)) AS klant_naam
     FROM kassa_verkopen kv LEFT JOIN gebruikers g ON g.id = kv.klant_id
     WHERE kv.id = ?`,
    [id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      if (!rows.length) return res.status(404).json({ error: 'Niet gevonden' });
      const verkoop = rows[0];
      db.query('SELECT naam, aantal, prijs_per_stuk FROM kassa_verkoop_regels WHERE verkoop_id = ? ORDER BY id',
        [id],
        (err2, regels) => {
          if (err2) return res.status(500).json({ error: 'DB fout' });
          res.json({ ...verkoop, regels });
        });
    });
});

// Verwijder kassa verkoop
app.delete('/api/kassa/verkopen/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Ongeldig id' });
  db.query('DELETE FROM kassa_verkoop_regels WHERE verkoop_id = ?', [id], (err) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    db.query('DELETE FROM kassa_verkopen WHERE id = ?', [id], (err2, result) => {
      if (err2) return res.status(500).json({ error: 'DB fout' });
      if (!result.affectedRows) return res.status(404).json({ error: 'Niet gevonden' });
      res.json({ success: true });
    });
  });
});

// Wijzig kassa verkoop
app.put('/api/kassa/verkopen/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Ongeldig id' });
  const { betaalmethode, klant_id, regels } = req.body || {};
  const methode = ['pin','cash','rekening'].includes(betaalmethode) ? betaalmethode : null;
  if (!methode) return res.status(400).json({ error: 'Ongeldige betaalmethode' });
  if (!regels || !regels.length) return res.status(400).json({ error: 'Geen regels' });
  const totaal = regels.reduce((s, r) => s + (parseFloat(r.aantal) * parseFloat(r.prijs_per_stuk)), 0);
  db.query('UPDATE kassa_verkopen SET betaalmethode=?, klant_id=?, totaal=? WHERE id=?',
    [methode, klant_id || null, totaal, id],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      if (!result.affectedRows) return res.status(404).json({ error: 'Niet gevonden' });
      db.query('DELETE FROM kassa_verkoop_regels WHERE verkoop_id = ?', [id], (err2) => {
        if (err2) return res.status(500).json({ error: 'DB fout regels' });
        const rows = regels.map(r => [id, r.product_id || null, r.naam, parseFloat(r.aantal), parseFloat(r.prijs_per_stuk)]);
        db.query('INSERT INTO kassa_verkoop_regels (verkoop_id, product_id, naam, aantal, prijs_per_stuk) VALUES ?',
          [rows],
          (err3) => {
            if (err3) return res.status(500).json({ error: 'DB fout regels' });
            res.json({ success: true, totaal });
          });
      });
    });
});

// Dag afsluiten
app.post('/api/kassa/dag-afsluiten', requireMedewerker, (req, res) => {
  const { notities } = req.body || {};
  db.query(`
    SELECT betaalmethode, SUM(totaal) AS som, COUNT(*) AS aantal
    FROM kassa_verkopen
    WHERE DATE(aangemaakt_op) = CURDATE()
    GROUP BY betaalmethode`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      const pinRij = rows.find(r => r.betaalmethode === 'pin');
      const cashRij = rows.find(r => r.betaalmethode === 'cash');
      const totaal_pin = pinRij ? parseFloat(pinRij.som) : 0;
      const totaal_cash = cashRij ? parseFloat(cashRij.som) : 0;
      const totaal = totaal_pin + totaal_cash;
      const aantal = rows.reduce((s, r) => s + r.aantal, 0);
      db.query(
        `INSERT INTO kassa_dag_afsluitingen (datum, totaal_pin, totaal_cash, totaal, aantal_transacties, notities)
         VALUES (CURDATE(), ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE totaal_pin=VALUES(totaal_pin), totaal_cash=VALUES(totaal_cash),
           totaal=VALUES(totaal), aantal_transacties=VALUES(aantal_transacties),
           notities=VALUES(notities), afgesloten_op=NOW()`,
        [totaal_pin, totaal_cash, totaal, aantal, notities || null],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'DB fout' });
          res.json({ success: true, totaal_pin, totaal_cash, totaal, aantal });
        });
    });
});

// Lijst afgesloten dagen
app.get('/api/kassa/dag-afsluitingen', requireMedewerker, (req, res) => {
  // Afgesloten dagen
  db.query('SELECT *, 0 AS open FROM kassa_dag_afsluitingen ORDER BY datum DESC LIMIT 90', (err, gesloten) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    // Open dagen: dagen met transacties die NIET in kassa_dag_afsluitingen staan
    db.query(`
      SELECT DATE(aangemaakt_op) AS datum,
             SUM(CASE WHEN betaalmethode='pin'  THEN totaal ELSE 0 END) AS totaal_pin,
             SUM(CASE WHEN betaalmethode='cash' THEN totaal ELSE 0 END) AS totaal_cash,
             SUM(totaal) AS totaal,
             COUNT(*) AS aantal_transacties,
             NULL AS notities, NULL AS afgesloten_op, NULL AS id,
             1 AS open
      FROM kassa_verkopen
      WHERE DATE(aangemaakt_op) NOT IN (SELECT datum FROM kassa_dag_afsluitingen)
      GROUP BY DATE(aangemaakt_op)
      ORDER BY datum DESC
      LIMIT 30`, (err2, openDagen) => {
      if (err2) return res.status(500).json({ error: 'DB fout' });
      // Combineer: open bovenaan, daarna afgesloten, gesorteerd op datum desc
      const alles = [...openDagen, ...gesloten].sort((a, b) => new Date(b.datum) - new Date(a.datum));
      res.json(alles);
    });
  });
});

// Detail van een afgesloten dag (transacties)
app.get('/api/kassa/dag-afsluitingen/:datum/transacties', requireMedewerker, (req, res) => {
  const datum = req.params.datum; // YYYY-MM-DD
  if (!/^\d{4}-\d{2}-\d{2}$/.test(datum)) return res.status(400).json({ error: 'Ongeldig datum formaat' });
  db.query(`
    SELECT kv.id, kv.betaalmethode, kv.totaal, kv.aangemaakt_op,
           GROUP_CONCAT(CONCAT(kvr.naam, ' x', kvr.aantal) ORDER BY kvr.id SEPARATOR ', ') AS regels_samenvatting
    FROM kassa_verkopen kv
    LEFT JOIN kassa_verkoop_regels kvr ON kvr.verkoop_id = kv.id
    WHERE DATE(kv.aangemaakt_op) = ?
    GROUP BY kv.id
    ORDER BY kv.aangemaakt_op DESC`,
    [datum],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json(rows);
    });
});

// ---- BEZORGCHECK (publiek) ----
app.get('/api/bezorgcheck', async (req, res) => {
  const raw = (req.query.postcode || '').trim().toUpperCase().replace(/\s/g, '');
  if (!/^\d{4}([A-Z]{2})?$/.test(raw)) return res.status(400).json({ error: 'Ongeldige postcode' });
  const pc4 = raw.slice(0, 4);

  try {
    const dbp = db.promise();

    // 1. Controleer of postcode expliciet in een zone staat
    const [zoneRows] = await dbp.query(`
      SELECT bp.toegestaan
      FROM bezorgzone_postcodes bp
      JOIN bezorgzones bz ON bp.zone_id = bz.id
      WHERE bz.actief = 1 AND (bp.postcode = ? OR bp.postcode = ?)
      ORDER BY LENGTH(bp.postcode) DESC, bp.toegestaan DESC
      LIMIT 1`, [raw, pc4]);

    if (zoneRows.length > 0) {
      return res.json({ status: zoneRows[0].toegestaan ? 'beschikbaar' : 'geblokkeerd' });
    }

    // 2. Niet in zones → controleer straal via geocoding
    const [irows] = await dbp.query(
      "SELECT sleutel, waarde FROM instellingen WHERE sleutel IN ('bezorg_postcode','bezorg_straal')"
    );
    const straal = parseFloat(irows.find(r => r.sleutel === 'bezorg_straal')?.waarde) || 0;
    const centerPc = (irows.find(r => r.sleutel === 'bezorg_postcode')?.waarde || '').trim();

    if (!straal || !centerPc) {
      return res.json({ status: 'geen_bezorging' });
    }

    // 3. Geocodeer beide postcodes en bereken afstand
    const [centerCoords, klantCoords] = await Promise.all([
      geocodePostcode(centerPc),
      geocodePostcode(raw)
    ]);

    if (!centerCoords || !klantCoords) {
      return res.json({ status: 'onbekend' });
    }

    const afstand = haversineKm(centerCoords, klantCoords);
    return res.json({ status: afstand <= straal ? 'beschikbaar' : 'geen_bezorging', afstand: Math.round(afstand * 10) / 10 });

  } catch(e) {
    return res.status(500).json({ error: 'DB fout' });
  }
});

// ---- BEZORGZONES ----
app.get('/api/bezorgzones', requireAdmin, (req, res) => {
  db.query('SELECT * FROM bezorgzones ORDER BY volgorde, naam', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json(rows);
  });
});

app.post('/api/bezorgzones', requireAdmin, (req, res) => {
  const { naam, prijs, actief } = req.body;
  if (!naam || naam.trim() === '') return res.status(400).json({ error: 'Naam verplicht' });
  db.query('INSERT INTO bezorgzones (naam, prijs, actief) VALUES (?,?,?)',
    [naam.trim(), parseFloat(prijs) || 0, actief ? 1 : 0],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ id: result.insertId });
    });
});

app.put('/api/bezorgzones/:id', requireAdmin, (req, res) => {
  const { naam, prijs, actief } = req.body;
  if (!naam || naam.trim() === '') return res.status(400).json({ error: 'Naam verplicht' });
  db.query('UPDATE bezorgzones SET naam=?, prijs=?, actief=? WHERE id=?',
    [naam.trim(), parseFloat(prijs) || 0, actief ? 1 : 0, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ ok: true });
    });
});

app.delete('/api/bezorgzones/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM bezorgzones WHERE id=?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json({ ok: true });
  });
});

// Proxy Overpass API (voorkomt CORS vanuit browser)
app.post('/api/overpass-proxy', requireAdmin, express.text({ type: '*/*', limit: '50kb' }), (req, res) => {
  const https = require('https');
  const body = req.body || '';
  const postData = 'data=' + encodeURIComponent(body);
  const options = {
    hostname: 'overpass-api.de',
    path: '/api/interpreter',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(postData),
      'User-Agent': 'webshop-admin/1.0'
    }
  };
  const request = https.request(options, (upstream) => {
    let data = '';
    upstream.on('data', chunk => { data += chunk; });
    upstream.on('end', () => {
      try { res.json(JSON.parse(data)); }
      catch { res.status(502).json({ error: 'Ongeldig antwoord van Overpass' }); }
    });
  });
  request.on('error', () => res.status(502).json({ error: 'Overpass niet bereikbaar' }));
  request.setTimeout(35000, () => { request.destroy(); res.status(504).json({ error: 'Timeout' }); });
  request.write(postData);
  request.end();
});

// Bulk-sync: voeg plaatsen toe die nog niet bestaan, raak bestaande niet aan
app.post('/api/bezorgzones/bulk-sync', requireAdmin, (req, res) => {
  const { namen } = req.body;
  if (!Array.isArray(namen) || !namen.length) return res.json({ added: 0, total: 0 });
  const uniek = [...new Set(namen.map(n => String(n).trim()).filter(Boolean))];
  let added = 0;
  let pending = uniek.length;
  uniek.forEach(naam => {
    db.query(
      'INSERT IGNORE INTO bezorgzones (naam, prijs, actief) VALUES (?, 0, 1)',
      [naam],
      (err, result) => {
        if (!err && result.affectedRows > 0) added++;
        pending--;
        if (pending === 0) res.json({ added, total: uniek.length });
      }
    );
  });
});

// ---- BEZORGZONE POSTCODES ----
app.get('/api/bezorgzones/:id/postcodes', requireAdmin, (req, res) => {
  db.query('SELECT * FROM bezorgzone_postcodes WHERE zone_id=? ORDER BY postcode', [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json(rows);
  });
});

app.post('/api/bezorgzones/:id/postcodes', requireAdmin, (req, res) => {
  const { postcode, toegestaan } = req.body;
  if (!postcode) return res.status(400).json({ error: 'Postcode verplicht' });
  const pc = postcode.trim().toUpperCase().replace(/\s/g, '');
  if (!/^\d{4}([A-Z]{2})?$/.test(pc)) return res.status(400).json({ error: 'Ongeldige postcode' });
  db.query('INSERT INTO bezorgzone_postcodes (zone_id, postcode, toegestaan) VALUES (?,?,?) ON DUPLICATE KEY UPDATE toegestaan=VALUES(toegestaan)',
    [req.params.id, pc, toegestaan ? 1 : 0],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ id: result.insertId });
    });
});

app.delete('/api/bezorgzone-postcodes/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM bezorgzone_postcodes WHERE id=?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json({ ok: true });
  });
});

// --- Backend API: gebruikers beheren (alleen admin) ---
app.get('/api/gebruikers', requireAdmin, (req, res) => {
  db.query('SELECT id, voornaam, achternaam, adres, huisnummer, postcode, woonplaats, email, telefoon, rol, uurtarief, kortingsklant, aangemaakt_op FROM gebruikers WHERE verwijderd_op IS NULL', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(results);
  });
});

app.get('/api/gebruikers/prullenbak', requireAdmin, (req, res) => {
  db.query('SELECT id, voornaam, achternaam, email, rol, verwijderd_op FROM gebruikers WHERE verwijderd_op IS NOT NULL ORDER BY verwijderd_op DESC', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(results);
  });
});

app.post('/api/gebruikers/herstel/:id', requireAdmin, (req, res) => {
  db.query('UPDATE gebruikers SET verwijderd_op = NULL WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

app.delete('/api/gebruikers/permanent/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM gebruikers WHERE id = ? AND verwijderd_op IS NOT NULL', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

// --- Backend API: producten beheren (medewerker + admin) ---
app.post('/api/producten', requireMedewerker, (req, res) => {
  const { artikelcode, naam, beschrijving, prijs, eenheid, voorraad_actueel,
          minimum_voorraad, magazijnloc, barcode, gewicht, groep_id, bezorging, korting } = req.body;
  const bezorgingVal = ['afhaal','zelf','post'].includes(bezorging) ? bezorging : 'afhaal';
  const kortingVal = [0, 5, 10].includes(parseInt(korting)) ? parseInt(korting) : 0;
  db.query(
    `INSERT INTO producten (artikelcode, naam, beschrijving, prijs, eenheid,
      voorraad_actueel, minimum_voorraad, magazijnloc, barcode, gewicht, groep_id, bezorging, korting)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [artikelcode || null, naam, beschrijving || null, prijs, eenheid || null,
     voorraad_actueel || 0, minimum_voorraad || 0, magazijnloc || null,
     barcode || null, gewicht || null, groep_id || null, bezorgingVal, kortingVal],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ id: result.insertId });
    }
  );
});

app.put('/api/producten/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const { artikelcode, naam, beschrijving, prijs, eenheid, voorraad_actueel,
          minimum_voorraad, magazijnloc, barcode, gewicht, groep_id, actief, leverancier_id, bezorging, korting } = req.body;
  const bezorgingVal = ['afhaal','zelf','post'].includes(bezorging) ? bezorging : 'afhaal';
  const kortingVal = [0, 5, 10].includes(parseInt(korting)) ? parseInt(korting) : 0;
  db.query(
    `UPDATE producten SET artikelcode=?, naam=?, beschrijving=?, prijs=?, eenheid=?,
      voorraad_actueel=?, minimum_voorraad=?, magazijnloc=?, barcode=?, gewicht=?, groep_id=?, actief=?, leverancier_id=?, bezorging=?, korting=?
     WHERE id=? AND verwijderd_op IS NULL`,
    [artikelcode || null, naam, beschrijving || null, prijs, eenheid || null,
     voorraad_actueel || 0, minimum_voorraad || 0, magazijnloc || null,
     barcode || null, gewicht || null, groep_id || null, actief ? 1 : 0, leverancier_id || null, bezorgingVal, kortingVal, id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ success: true });
    }
  );
});

app.delete('/api/producten/:id', requireMedewerker, (req, res) => {
  db.query('UPDATE producten SET verwijderd_op = NOW() WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

// --- Product afbeeldingen ---
app.get('/api/producten/:id/afbeeldingen', requireMedewerker, (req, res) => {
  db.query(
    'SELECT id, bestandsnaam, volgorde FROM product_afbeeldingen WHERE product_id = ? ORDER BY volgorde, id',
    [parseInt(req.params.id)],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(results);
    }
  );
});

app.post('/api/producten/:id/afbeeldingen', requireMedewerker, productUpload.array('afbeeldingen', 20), (req, res) => {
  const productId = parseInt(req.params.id);
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Geen bestand' });
  const values = req.files.map((f, i) => [productId, f.filename, i]);
  db.query('INSERT INTO product_afbeeldingen (product_id, bestandsnaam, volgorde) VALUES ?', [values], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true, aantal: req.files.length });
  });
});

app.delete('/api/producten/:id/afbeeldingen/:afbId', requireMedewerker, (req, res) => {
  const productId = parseInt(req.params.id);
  const afbId    = parseInt(req.params.afbId);
  db.query('SELECT bestandsnaam FROM product_afbeeldingen WHERE id = ? AND product_id = ?', [afbId, productId], (err, rows) => {
    if (err || rows.length === 0) return res.status(404).json({ error: 'Niet gevonden' });
    const bestand = path.join(__dirname, 'public', 'producten', rows[0].bestandsnaam);
    db.query('DELETE FROM product_afbeeldingen WHERE id = ?', [afbId], (err2) => {
      if (err2) return res.status(500).json({ error: 'Database fout' });
      const fs = require('fs');
      fs.unlink(bestand, () => {}); // stille fail als bestand al weg is
      res.json({ success: true });
    });
  });
});

// --- Leveranciers per product (meerdere) ---
app.get('/api/producten/:id/leveranciers', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  db.query(
    'SELECT l.id, l.naam FROM product_leveranciers pl JOIN leveranciers l ON pl.leverancier_id = l.id WHERE pl.product_id = ? ORDER BY l.naam',
    [id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json(rows);
    }
  );
});

app.put('/api/producten/:id/leveranciers', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const ids = Array.isArray(req.body.ids) ? req.body.ids.map(x => parseInt(x)).filter(x => x > 0) : [];
  const dbp = db.promise();
  dbp.query('DELETE FROM product_leveranciers WHERE product_id = ?', [id])
    .then(() => {
      const eersteId = ids[0] || null;
      const updates = [dbp.query('UPDATE producten SET leverancier_id = ? WHERE id = ?', [eersteId, id])];
      if (ids.length > 0) {
        const rows = ids.map(lid => [id, lid]);
        updates.push(dbp.query('INSERT INTO product_leveranciers (product_id, leverancier_id) VALUES ?', [rows]));
      }
      return Promise.all(updates);
    })
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'DB fout' }));
});

// --- API: eenheden (openbaar leesbaar, beheer vereist admin) ---
app.get('/api/eenheden', (req, res) => {
  db.query('SELECT id, naam, omschrijving FROM eenheden ORDER BY naam', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(results);
  });
});

app.post('/api/eenheden', requireAdmin, (req, res) => {
  const naam = (req.body.naam || '').trim().slice(0, 50);
  const omschrijving = (req.body.omschrijving || '').trim().slice(0, 100) || null;
  if (!naam) return res.status(400).json({ error: 'Naam verplicht' });
  db.query('INSERT INTO eenheden (naam, omschrijving) VALUES (?, ?)', [naam, omschrijving], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Naam bestaat al' });
      return res.status(500).json({ error: 'Database fout' });
    }
    res.json({ id: result.insertId, naam, omschrijving });
  });
});

app.put('/api/eenheden/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const naam = (req.body.naam || '').trim().slice(0, 50);
  const omschrijving = (req.body.omschrijving || '').trim().slice(0, 100) || null;
  if (!naam) return res.status(400).json({ error: 'Naam verplicht' });
  db.query('UPDATE eenheden SET naam=?, omschrijving=? WHERE id=?', [naam, omschrijving, id], (err) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Naam bestaat al' });
      return res.status(500).json({ error: 'Database fout' });
    }
    res.json({ success: true });
  });
});

app.delete('/api/eenheden/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM eenheden WHERE id=?', [parseInt(req.params.id)], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

// --- Backend API: productgroepen (medewerker + admin) ---
app.get('/api/productgroepen', requireMedewerker, (req, res) => {
  db.query(`SELECT pg.id, pg.naam, pg.beschrijving, pg.parent_id, pg.level, pg.sort_order, pg.aangemaakt_op,
    (pg.image_thumbnail IS NOT NULL) AS heeft_afbeelding,
    (SELECT pa.bestandsnaam FROM product_afbeeldingen pa
     JOIN producten p ON pa.product_id = p.id
     WHERE p.verwijderd_op IS NULL
       AND p.groep_id IN (
         SELECT g2.id FROM productgroepen g2
         WHERE g2.id = pg.id
            OR g2.parent_id = pg.id
            OR g2.parent_id IN (
              SELECT g3.id FROM productgroepen g3 WHERE g3.parent_id = pg.id
            )
       )
     ORDER BY pa.volgorde, pa.id LIMIT 1) AS afbeelding
    FROM productgroepen pg WHERE pg.verwijderd_op IS NULL ORDER BY pg.level, pg.sort_order, pg.naam`, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(results);
  });
});

app.get('/api/productgroepen/:id', requireMedewerker, (req, res) => {
  db.query('SELECT id, naam, beschrijving, parent_id, level, sort_order, aangemaakt_op FROM productgroepen WHERE id = ?', [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    if (results.length === 0) return res.status(404).json({ error: 'Niet gevonden' });
    res.json(results[0]);
  });
});

app.get('/api/productgroepen/prullenbak', requireMedewerker, (req, res) => {
  db.query('SELECT * FROM productgroepen WHERE verwijderd_op IS NOT NULL ORDER BY verwijderd_op DESC', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(results);
  });
});

app.post('/api/productgroepen/herstel/:id', requireMedewerker, (req, res) => {
  db.query('UPDATE productgroepen SET verwijderd_op = NULL WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

app.delete('/api/productgroepen/permanent/:id', requireMedewerker, (req, res) => {
  db.query('DELETE FROM productgroepen WHERE id = ? AND verwijderd_op IS NOT NULL', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

app.post('/api/productgroepen', requireMedewerker, groepUpload.single('afbeelding'), (req, res) => {
  const { naam, beschrijving, parent_id } = req.body;
  if (!naam) return res.status(400).json({ error: 'Naam is verplicht.' });
  const parentVal = parent_id || null;
  const imageBuffer = req.file ? req.file.buffer : null;
  const doInsert = (level) => {
    db.query(
      'INSERT INTO productgroepen (naam, beschrijving, parent_id, level, image_thumbnail) VALUES (?, ?, ?, ?, ?)',
      [naam, beschrijving || null, parentVal, level, imageBuffer],
      (err2, result) => {
        if (err2) return res.status(500).json({ error: 'Database fout' });
        res.json({ id: result.insertId, naam, beschrijving, parent_id: parentVal, level });
      });
  };
  if (parentVal) {
    db.query('SELECT level FROM productgroepen WHERE id = ?', [parentVal], (err, rows) => {
      if (err || rows.length === 0) return res.status(400).json({ error: 'Ongeldige bovenliggende groep.' });
      doInsert(rows[0].level + 1);
    });
  } else {
    doInsert(1);
  }
});

app.put('/api/productgroepen/:id', requireMedewerker, groepUpload.single('afbeelding'), (req, res) => {
  const { naam, beschrijving, parent_id } = req.body;
  if (!naam) return res.status(400).json({ error: 'Naam is verplicht.' });
  const parentVal = parent_id || null;
  const doUpdate = (level) => {
    if (req.file) {
      db.query('UPDATE productgroepen SET naam=?, beschrijving=?, parent_id=?, level=?, image_thumbnail=? WHERE id=?',
        [naam, beschrijving || null, parentVal, level, req.file.buffer, req.params.id], (err) => {
          if (err) return res.status(500).json({ error: 'Database fout' });
          res.json({ success: true });
        });
    } else {
      db.query('UPDATE productgroepen SET naam=?, beschrijving=?, parent_id=?, level=? WHERE id=?',
        [naam, beschrijving || null, parentVal, level, req.params.id], (err) => {
          if (err) return res.status(500).json({ error: 'Database fout' });
          res.json({ success: true });
        });
    }
  };
  if (parentVal) {
    db.query('SELECT level FROM productgroepen WHERE id = ?', [parentVal], (err, rows) => {
      if (err || rows.length === 0) return res.status(400).json({ error: 'Ongeldige bovenliggende groep.' });
      doUpdate(rows[0].level + 1);
    });
  } else {
    doUpdate(1);
  }
});

app.delete('/api/productgroepen/:id', requireMedewerker, (req, res) => {
  db.query('UPDATE productgroepen SET verwijderd_op = NOW() WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

// --- Backend API: gebruikers beheren (admin) ---
app.post('/api/gebruikers', requireAdmin, (req, res) => {
  const { voornaam, achternaam, adres, huisnummer, postcode, woonplaats, email, telefoon, wachtwoord, rol, uurtarief, kortingsklant } = req.body;
  if (!voornaam || !email || !wachtwoord) return res.status(400).json({ error: 'Voornaam, e-mail en wachtwoord zijn verplicht.' });
  if (wachtwoord.length < 8) return res.status(400).json({ error: 'Wachtwoord moet minimaal 8 tekens zijn.' });
  if (!['admin', 'medewerker', 'klant'].includes(rol)) return res.status(400).json({ error: 'Ongeldig rol.' });
  const hash = bcrypt.hashSync(wachtwoord, 10);
  db.query(
    'INSERT INTO gebruikers (voornaam, achternaam, adres, huisnummer, postcode, woonplaats, email, telefoon, wachtwoord, rol, uurtarief, kortingsklant) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [voornaam, achternaam || '', adres || null, huisnummer || null, postcode || null, woonplaats || null, email.trim(), telefoon || null, hash, rol || 'klant', uurtarief != null && uurtarief !== '' ? parseFloat(uurtarief) : null, kortingsklant ? 1 : 0],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database fout of e-mail bestaat al' });
      res.json({ id: result.insertId, voornaam, achternaam, email, rol: rol || 'klant' });
    });
});

app.delete('/api/gebruikers/:id', requireAdmin, (req, res) => {
  db.query('UPDATE gebruikers SET verwijderd_op = NOW() WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ success: true });
  });
});

app.put('/api/gebruikers/:id', requireAdmin, (req, res) => {
  const { voornaam, achternaam, adres, huisnummer, postcode, woonplaats, email, telefoon, wachtwoord, rol, uurtarief, kortingsklant } = req.body;
  if (!voornaam || !email) return res.status(400).json({ error: 'Voornaam en e-mail zijn verplicht.' });
  if (!['admin', 'medewerker', 'klant'].includes(rol)) return res.status(400).json({ error: 'Ongeldig rol.' });
  const tarief = uurtarief != null && uurtarief !== '' ? parseFloat(uurtarief) : null;
  const korting = kortingsklant ? 1 : 0;
  if (wachtwoord) {
    const hash = bcrypt.hashSync(wachtwoord, 10);
    db.query(
      'UPDATE gebruikers SET voornaam=?, achternaam=?, adres=?, huisnummer=?, postcode=?, woonplaats=?, email=?, telefoon=?, wachtwoord=?, rol=?, uurtarief=?, kortingsklant=? WHERE id=?',
      [voornaam, achternaam || '', adres || null, huisnummer || null, postcode || null, woonplaats || null, email, telefoon || null, hash, rol, tarief, korting, req.params.id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database fout of e-mail bestaat al' });
        res.json({ success: true });
      });
  } else {
    db.query(
      'UPDATE gebruikers SET voornaam=?, achternaam=?, adres=?, huisnummer=?, postcode=?, woonplaats=?, email=?, telefoon=?, rol=?, uurtarief=?, kortingsklant=? WHERE id=?',
      [voornaam, achternaam || '', adres || null, huisnummer || null, postcode || null, woonplaats || null, email, telefoon || null, rol, tarief, korting, req.params.id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database fout of e-mail bestaat al' });
        res.json({ success: true });
      });
  }
});

// ============================================================
// NAS IMPORT — Verbinding via SSH-tunnel naar Synology NAS
// ============================================================

const NAS_SSH_HOST = '100.113.70.121';
const NAS_SSH_USER = 'houthandel veenstra';
const NAS_SSH_KEY  = '/root/.ssh/nas_key';
const NAS_MYSQL    = '/usr/local/mariadb10/bin/mysql';

// Voer een SQL-query uit op de NAS via SSH, geeft rows terug als array van objecten
function nasQuery(dbUser, dbPass, database, sql) {
  return new Promise((resolve, reject) => {
    const ssh = new SshClient();
    ssh.on('ready', () => {
      const cmd = `${NAS_MYSQL} -u ${dbUser} -p'${dbPass.replace(/'/g, "'\\''")}' ${database} --batch --skip-column-names -e ${JSON.stringify(sql)}`;
      ssh.exec(cmd, (err, stream) => {
        if (err) { ssh.end(); return reject(err); }
        let out = '', errOut = '';
        stream.on('data', d => out += d);
        stream.stderr.on('data', d => errOut += d);
        stream.on('close', () => {
          ssh.end();
          if (errOut && !out) return reject(new Error(errOut.trim()));
          resolve(out.trim());
        });
      });
    });
    ssh.on('error', reject);
    ssh.connect({
      host: NAS_SSH_HOST,
      port: 22,
      username: NAS_SSH_USER,
      privateKey: fs.readFileSync(NAS_SSH_KEY),
      readyTimeout: 10000
    });
  });
}

// Parse MySQL --batch output naar array van objecten
function parseMysqlBatch(output, kolommen) {
  if (!output) return [];
  return output.split('\n').map(line => {
    const vals = line.split('\t');
    const obj = {};
    kolommen.forEach((k, i) => obj[k] = vals[i] === 'NULL' ? null : (vals[i] ?? null));
    return obj;
  });
}

// Haal kolomnamen op van een tabel
async function nasKolommen(dbUser, dbPass, database, tabel) {
  const out = await nasQuery(dbUser, dbPass, database,
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='${database}' AND TABLE_NAME='${tabel}' ORDER BY ORDINAL_POSITION`);
  return out ? out.split('\n').map(r => r.trim()).filter(Boolean) : [];
}

// Test verbinding + haal tabellen op
app.post('/api/nas/verbind', requireAdmin, async (req, res) => {
  const { user, password, database } = req.body;
  if (!user || !database) return res.status(400).json({ error: 'Gebruiker en database zijn verplicht.' });
  try {
    const out = await nasQuery(user, password || '', database, 'SHOW TABLES');
    const tabellen = out ? out.split('\n').map(r => r.trim()).filter(Boolean) : [];
    res.json({ success: true, tabellen });
  } catch (err) {
    res.status(503).json({ error: 'Kan geen verbinding maken: ' + (err.message || String(err)) });
  }
});

// Haal preview van een tabel op (eerste 10 rijen)
app.post('/api/nas/preview', requireAdmin, async (req, res) => {
  const { user, password, database, tabel } = req.body;
  if (!user || !database || !tabel) return res.status(400).json({ error: 'Ontbrekende gegevens.' });
  const veiligeTabel = tabel.replace(/[`'\\]/g, '');
  try {
    const kolommen = await nasKolommen(user, password || '', database, veiligeTabel);
    const out = await nasQuery(user, password || '', database, `SELECT * FROM \`${veiligeTabel}\` LIMIT 10`);
    const rows = parseMysqlBatch(out, kolommen);
    res.json({ rows, kolommen });
  } catch (err) {
    res.status(503).json({ error: 'Fout: ' + (err.message || String(err)) });
  }
});

// Kopieer tabel-data naar lokale webshop DB
app.post('/api/nas/kopieer', requireAdmin, async (req, res) => {
  const { user, password, database, tabel, mapping } = req.body;
  if (!user || !database || !tabel || !mapping) return res.status(400).json({ error: 'Ontbrekende gegevens.' });
  const TOEGESTANE_DOELEN = ['producten', 'productgroepen', 'gebruikers'];
  if (!TOEGESTANE_DOELEN.includes(mapping.doel)) return res.status(400).json({ error: 'Ongeldig doel.' });

  const veiligeTabel = tabel.replace(/[`'\\]/g, '');
  try {
    const kolommen = await nasKolommen(user, password || '', database, veiligeTabel);
    const out = await nasQuery(user, password || '', database, `SELECT * FROM \`${veiligeTabel}\``);
    const rows = parseMysqlBatch(out, kolommen);
    if (!rows.length) return res.json({ gekopieerd: 0, fouten: 0, totaal: 0 });

    const kol = mapping.kolommen;
    const dbPromise = db.promise();
    let gekopieerd = 0, fouten = 0;

    for (const row of rows) {
      const waarden = {};
      for (const [lokaal, nas_veld] of Object.entries(kol)) {
        waarden[lokaal] = row[nas_veld] !== undefined ? row[nas_veld] : null;
      }
      if (waarden.wachtwoord && !String(waarden.wachtwoord).startsWith('$2')) {
        waarden.wachtwoord = bcrypt.hashSync(String(waarden.wachtwoord), 10);
      }
      const velden = Object.keys(waarden).map(k => `\`${k}\``).join(', ');
      const placeholders = Object.keys(waarden).map(() => '?').join(', ');
      try {
        await dbPromise.query(
          `INSERT IGNORE INTO \`${mapping.doel}\` (${velden}) VALUES (${placeholders})`,
          Object.values(waarden)
        );
        gekopieerd++;
      } catch (_) { fouten++; }
    }
    res.json({ gekopieerd, fouten, totaal: rows.length });
  } catch (err) {
    res.status(503).json({ error: 'Fout: ' + (err.message || String(err)) });
  }
});

// ---- INSTELLINGEN API (publiek lezen, admin schrijven) ----
app.get('/api/instellingen', (req, res) => {
  db.query('SELECT sleutel, waarde FROM instellingen', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    const obj = {};
    rows.forEach(r => { obj[r.sleutel] = r.waarde; });
    res.json(obj);
  });
});

app.put('/api/instellingen', requireAdmin, (req, res) => {
  const updates = req.body; // { sleutel: waarde, ... }
  if (typeof updates !== 'object' || Array.isArray(updates))
    return res.status(400).json({ error: 'Ongeldig formaat' });
  const keys = Object.keys(updates);
  if (keys.length === 0) return res.json({ ok: true });
  const toegestaan = ['bedrijf_naam','adres_straat','adres_postcode','adres_stad',
    'telefoon','whatsapp','email','kvk','btw','maps_url','openingstijden','aangepaste_tijden',
    'winkel_modus',
    'mail_gmail','mail_app_ww',
    'bezorg_postcode','bezorg_straal'];
  for (const k of keys) {
    if (!toegestaan.includes(k)) return res.status(400).json({ error: 'Onbekende sleutel: ' + k });
  }
  const waarden = keys.map(k => [k, String(updates[k])]);
  db.query(
    'INSERT INTO instellingen (sleutel, waarde) VALUES ? ON DUPLICATE KEY UPDATE waarde = VALUES(waarde)',
    [waarden],
    (err) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ ok: true });
    }
  );
});

// ---- MAIL TEST ----
app.post('/api/mail/test', requireAdmin, (req, res) => {
  const naar = req.body && req.body.naar ? String(req.body.naar).trim() : null;
  if (!naar || !naar.includes('@')) return res.status(400).json({ error: 'Geen geldig e-mailadres opgegeven' });
  db.query('SELECT sleutel, waarde FROM instellingen WHERE sleutel IN (?,?)',
    ['mail_gmail','mail_app_ww'],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      const s = {};
      rows.forEach(r => s[r.sleutel] = r.waarde);
      if (!s.mail_gmail || !s.mail_app_ww)
        return res.status(400).json({ error: 'Gmail adres en app-wachtwoord zijn nog niet ingesteld' });
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: s.mail_gmail, pass: s.mail_app_ww }
      });
      const ontvanger = naar;
      transporter.sendMail({
        from: s.mail_gmail,
        to: ontvanger,
        subject: 'Test e-mail vanuit webshop',
        text: 'De mail verbinding werkt correct.'
      }, (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ ok: true });
      });
    }
  );
});

// ---- OFFERTE AANVRAGEN ----
// Publiek: offerte indienen
app.post('/api/offerte', (req, res) => {
  const { naam, email, telefoon, bericht, producten } = req.body;
  if (!naam || !email || !Array.isArray(producten) || producten.length === 0)
    return res.status(400).json({ error: 'Naam, email en producten zijn verplicht' });
  const naamTrimmed = String(naam).trim().slice(0, 120);
  const emailTrimmed = String(email).trim().slice(0, 200);
  const telTrimmed = telefoon ? String(telefoon).trim().slice(0, 40) : null;
  const berichtTrimmed = bericht ? String(bericht).trim().slice(0, 2000) : null;
  db.query(
    'INSERT INTO offerte_aanvragen (naam, email, telefoon, bericht, producten) VALUES (?, ?, ?, ?, ?)',
    [naamTrimmed, emailTrimmed, telTrimmed, berichtTrimmed, JSON.stringify(producten)],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ ok: true });
    }
  );
});

// Admin: offertes ophalen (niet verwijderd)
app.get('/api/offerte', requireMedewerker, (req, res) => {
  db.query(
    'SELECT id, naam, email, telefoon, bericht, producten, status, aangemaakt_op FROM offerte_aanvragen WHERE verwijderd_op IS NULL ORDER BY aangemaakt_op DESC',
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(rows);
    }
  );
});

// Admin: prullenbak offertes
app.get('/api/offerte/prullenbak', requireMedewerker, (req, res) => {
  db.query(
    'SELECT id, naam, email, producten, status, aangemaakt_op, verwijderd_op FROM offerte_aanvragen WHERE verwijderd_op IS NOT NULL ORDER BY verwijderd_op DESC',
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(rows);
    }
  );
});

// Admin: status updaten
app.put('/api/offerte/:id/status', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const { status } = req.body;
  if (!['nieuw', 'geaccepteerd', 'afgewezen'].includes(status))
    return res.status(400).json({ error: 'Ongeldige status' });
  db.query('UPDATE offerte_aanvragen SET status=? WHERE id=?', [status, id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ ok: true });
  });
});

// Admin: offerte gegevens bijwerken
app.put('/api/offerte/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const naam = req.body.naam ? String(req.body.naam).trim().slice(0, 200) : null;
  const email = req.body.email ? String(req.body.email).trim().slice(0, 200) : null;
  const telefoon = req.body.telefoon ? String(req.body.telefoon).trim().slice(0, 50) : '';
  const bericht = req.body.bericht ? String(req.body.bericht).trim().slice(0, 5000) : '';
  const status = req.body.status;
  if (!naam || !email) return res.status(400).json({ error: 'Naam en e-mail zijn verplicht' });
  if (!['nieuw', 'geaccepteerd', 'afgewezen'].includes(status)) return res.status(400).json({ error: 'Ongeldige status' });
  db.query('UPDATE offerte_aanvragen SET naam=?, email=?, telefoon=?, bericht=?, status=? WHERE id=?',
    [naam, email, telefoon, bericht, status, id], (err) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ ok: true });
    });
});

// Admin: offerte naar prullenbak (soft delete)
app.delete('/api/offerte/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  db.query('UPDATE offerte_aanvragen SET verwijderd_op=NOW() WHERE id=?', [id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ ok: true });
  });
});

// Admin: offerte herstellen uit prullenbak
app.put('/api/offerte/:id/herstel', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  db.query('UPDATE offerte_aanvragen SET verwijderd_op=NULL WHERE id=?', [id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ ok: true });
  });
});

// Admin: offerte definitief verwijderen
app.delete('/api/offerte/:id/definitief', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  db.query('DELETE FROM offerte_aanvragen WHERE id=?', [id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ ok: true });
  });
});

// ---- LEVERANCIERS ----
app.get('/api/leveranciers', requireMedewerker, (req, res) => {
  db.query('SELECT * FROM leveranciers ORDER BY naam', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json(rows);
  });
});

app.post('/api/leveranciers', requireMedewerker, (req, res) => {
  const naam = req.body.naam ? String(req.body.naam).trim().slice(0, 200) : null;
  if (!naam) return res.status(400).json({ error: 'Naam is verplicht' });
  const contactpersoon = String(req.body.contactpersoon || '').trim().slice(0, 200);
  const email = String(req.body.email || '').trim().slice(0, 200);
  const telefoon = String(req.body.telefoon || '').trim().slice(0, 50);
  const website = String(req.body.website || '').trim().slice(0, 300);
  const straat = String(req.body.straat || '').trim().slice(0, 200);
  const huisnummer = String(req.body.huisnummer || '').trim().slice(0, 20);
  const postcode = String(req.body.postcode || '').trim().slice(0, 10);
  const stad = String(req.body.stad || '').trim().slice(0, 100);
  const kvk = String(req.body.kvk || '').trim().slice(0, 50);
  const btw = String(req.body.btw || '').trim().slice(0, 50);
  const iban = String(req.body.iban || '').trim().slice(0, 34);
  const notities = String(req.body.notities || '').trim().slice(0, 5000);
  db.query('INSERT INTO leveranciers (naam, contactpersoon, email, telefoon, website, straat, huisnummer, postcode, stad, kvk, btw, iban, notities) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
    [naam, contactpersoon, email, telefoon, website, straat, huisnummer, postcode, stad, kvk, btw, iban, notities], (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ id: result.insertId });
    });
});

app.put('/api/leveranciers/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const naam = req.body.naam ? String(req.body.naam).trim().slice(0, 200) : null;
  if (!naam) return res.status(400).json({ error: 'Naam is verplicht' });
  const contactpersoon = String(req.body.contactpersoon || '').trim().slice(0, 200);
  const email = String(req.body.email || '').trim().slice(0, 200);
  const telefoon = String(req.body.telefoon || '').trim().slice(0, 50);
  const website = String(req.body.website || '').trim().slice(0, 300);
  const straat = String(req.body.straat || '').trim().slice(0, 200);
  const huisnummer = String(req.body.huisnummer || '').trim().slice(0, 20);
  const postcode = String(req.body.postcode || '').trim().slice(0, 10);
  const stad = String(req.body.stad || '').trim().slice(0, 100);
  const kvk = String(req.body.kvk || '').trim().slice(0, 50);
  const btw = String(req.body.btw || '').trim().slice(0, 50);
  const iban = String(req.body.iban || '').trim().slice(0, 34);
  const notities = String(req.body.notities || '').trim().slice(0, 5000);
  db.query('UPDATE leveranciers SET naam=?, contactpersoon=?, email=?, telefoon=?, website=?, straat=?, huisnummer=?, postcode=?, stad=?, kvk=?, btw=?, iban=?, notities=? WHERE id=?',
    [naam, contactpersoon, email, telefoon, website, straat, huisnummer, postcode, stad, kvk, btw, iban, notities, id], (err) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ ok: true });
    });
});

app.delete('/api/leveranciers/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  db.query('UPDATE producten SET leverancier_id=NULL WHERE leverancier_id=?', [id], () => {
    db.query('DELETE FROM leveranciers WHERE id=?', [id], (err) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ ok: true });
    });
  });
});

// ---- KLUSSEN ----
app.get('/api/klussen', requireMedewerker, (req, res) => {
  const q = (req.query.q || '').trim();
  const zoek = q ? `%${q}%` : null;
  const sql = zoek
    ? `SELECT k.id, k.naam, k.status, k.aangemaakt_op, k.klant_id,
              CONCAT(g.voornaam, IF(g.achternaam != '', CONCAT(' ', g.achternaam), '')) AS klant_naam
       FROM klussen k LEFT JOIN gebruikers g ON k.klant_id = g.id
       WHERE k.naam LIKE ? OR g.voornaam LIKE ? OR g.achternaam LIKE ? OR g.email LIKE ?
       ORDER BY k.aangemaakt_op DESC`
    : `SELECT k.id, k.naam, k.status, k.aangemaakt_op, k.klant_id,
              CONCAT(g.voornaam, IF(g.achternaam != '', CONCAT(' ', g.achternaam), '')) AS klant_naam
       FROM klussen k LEFT JOIN gebruikers g ON k.klant_id = g.id
       ORDER BY k.aangemaakt_op DESC`;
  const params = zoek ? [zoek, zoek, zoek, zoek] : [];
  db.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json(rows);
  });
});

app.post('/api/klussen', requireMedewerker, (req, res) => {
  const { naam, klant_id } = req.body;
  if (!naam || !naam.trim()) return res.status(400).json({ error: 'Naam is verplicht' });
  db.query('INSERT INTO klussen (naam, klant_id) VALUES (?, ?)',
    [naam.trim(), klant_id || null],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ id: result.insertId });
    });
});

app.put('/api/klussen/:id', requireMedewerker, (req, res) => {
  const id = parseInt(req.params.id);
  const { naam, klant_id, status } = req.body;
  if (!naam || !naam.trim()) return res.status(400).json({ error: 'Naam is verplicht' });
  db.query('UPDATE klussen SET naam=?, klant_id=?, status=? WHERE id=?',
    [naam.trim(), klant_id || null, status || 'open', id],
    (err) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ ok: true });
    });
});

app.delete('/api/klussen/:id', requireMedewerker, (req, res) => {
  db.query('DELETE FROM klussen WHERE id=?', [parseInt(req.params.id)], (err) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json({ ok: true });
  });
});

// Klanten zoeken voor klus-koppeling
app.get('/api/klanten/zoek', requireMedewerker, (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length === 0) {
    // geen filter → top 20 klanten
    db.query(
      `SELECT id, voornaam, achternaam, email FROM gebruikers
       WHERE verwijderd_op IS NULL AND rol='klant'
       ORDER BY voornaam, achternaam LIMIT 20`,
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB fout' });
        res.json(rows);
      });
    return;
  }
  const zoek = `%${q}%`;
  db.query(
    `SELECT id, voornaam, achternaam, email FROM gebruikers
     WHERE verwijderd_op IS NULL AND rol='klant'
       AND (voornaam LIKE ? OR achternaam LIKE ? OR email LIKE ?)
     ORDER BY voornaam, achternaam LIMIT 20`,
    [zoek, zoek, zoek],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json(rows);
    });
});

// ---- URENREGISTRATIE ----
app.get('/api/uren', requireMedewerker, (req, res) => {
  const { medewerker_id, klus_id, datum_van, datum_tot } = req.query;
  let sql = `SELECT u.id, u.datum, u.uren, u.starttijd, u.eindtijd, u.pauze, u.omschrijving, u.aangemaakt_op,
    u.medewerker_id, CONCAT(g.voornaam, IF(g.achternaam!='',CONCAT(' ',g.achternaam),'')) AS medewerker_naam, g.uurtarief,
    u.klus_id, k.naam AS klus_naam
    FROM urenregistraties u
    JOIN gebruikers g ON u.medewerker_id = g.id
    LEFT JOIN klussen k ON u.klus_id = k.id
    WHERE 1=1`;
  const params = [];
  if (medewerker_id) { sql += ' AND u.medewerker_id=?'; params.push(medewerker_id); }
  if (klus_id)       { sql += ' AND u.klus_id=?';       params.push(klus_id); }
  if (datum_van)     { sql += ' AND u.datum>=?';         params.push(datum_van); }
  if (datum_tot)     { sql += ' AND u.datum<=?';         params.push(datum_tot); }
  sql += ' ORDER BY u.datum DESC, u.id DESC';
  db.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json(rows);
  });
});

app.get('/api/uren/:id', requireMedewerker, (req, res) => {
  const sql = `SELECT u.id, u.datum, u.uren, u.starttijd, u.eindtijd, u.pauze, u.omschrijving, u.aangemaakt_op,
    u.medewerker_id, CONCAT(g.voornaam, IF(g.achternaam!='',CONCAT(' ',g.achternaam),'')) AS medewerker_naam, g.uurtarief,
    u.klus_id, k.naam AS klus_naam
    FROM urenregistraties u
    JOIN gebruikers g ON u.medewerker_id = g.id
    LEFT JOIN klussen k ON u.klus_id = k.id
    WHERE u.id=?`;
  db.query(sql, [parseInt(req.params.id)], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    if (!rows.length) return res.status(404).json({ error: 'Niet gevonden' });
    res.json(rows[0]);
  });
});

app.post('/api/uren', requireMedewerker, (req, res) => {
  const { medewerker_id, klus_id, datum, uren, starttijd, eindtijd, pauze, omschrijving } = req.body;
  if (!medewerker_id || !datum || !uren) return res.status(400).json({ error: 'Medewerker, datum en uren zijn verplicht' });
  db.query('INSERT INTO urenregistraties (medewerker_id, klus_id, datum, uren, starttijd, eindtijd, pauze, omschrijving) VALUES (?,?,?,?,?,?,?,?)',
    [medewerker_id, klus_id || null, datum, parseFloat(uren), starttijd || null, eindtijd || null, parseInt(pauze) || 0, omschrijving || null],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ id: result.insertId });
    });
});

app.put('/api/uren/:id', requireMedewerker, (req, res) => {
  const { medewerker_id, klus_id, datum, uren, starttijd, eindtijd, pauze, omschrijving } = req.body;
  if (!medewerker_id || !datum || !uren) return res.status(400).json({ error: 'Medewerker, datum en uren zijn verplicht' });
  db.query('UPDATE urenregistraties SET medewerker_id=?, klus_id=?, datum=?, uren=?, starttijd=?, eindtijd=?, pauze=?, omschrijving=? WHERE id=?',
    [medewerker_id, klus_id || null, datum, parseFloat(uren), starttijd || null, eindtijd || null, parseInt(pauze) || 0, omschrijving || null, parseInt(req.params.id)],
    (err) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ ok: true });
    });
});

app.delete('/api/uren/:id', requireMedewerker, (req, res) => {
  db.query('DELETE FROM urenregistraties WHERE id=?', [parseInt(req.params.id)], (err) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json({ ok: true });
  });
});

// ---- PRINTER RAW TCP (Epson TM-T20III netwerk) ----
app.post('/api/printer/raw', requireAdmin, (req, res) => {
  const { ip, port, data } = req.body;
  // Basis validatie: IP formaat en data array
  if (!ip || !Array.isArray(data) || data.length === 0) {
    return res.status(400).json({ error: 'ip en data zijn verplicht' });
  }
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    return res.status(400).json({ error: 'Ongeldig IP-adres formaat' });
  }
  const printerPort = parseInt(port) || 9100;
  if (printerPort < 1 || printerPort > 65535) {
    return res.status(400).json({ error: 'Ongeldig poortnummer' });
  }
  const socket = new net.Socket();
  let done = false;
  socket.setTimeout(5000);
  socket.connect(printerPort, ip, () => {
    socket.write(Buffer.from(data));
    socket.end();
    if (!done) { done = true; res.json({ ok: true }); }
  });
  socket.on('error', (err) => {
    if (!done) { done = true; res.status(500).json({ error: err.message }); }
  });
  socket.on('timeout', () => {
    socket.destroy();
    if (!done) { done = true; res.status(504).json({ error: 'Timeout — printer niet bereikbaar op ' + ip + ':' + printerPort }); }
  });
});

// Medewerkers ophalen voor urenregistratie dropdown
app.get('/api/medewerkers', requireMedewerker, (req, res) => {
  db.query(
    `SELECT id, voornaam, achternaam, email FROM gebruikers
     WHERE verwijderd_op IS NULL AND rol IN ('admin','medewerker')
     ORDER BY voornaam, achternaam`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json(rows);
    });
});

// ---- KLUS PRODUCTEN ----
app.get('/api/klussen/:id/producten', requireMedewerker, (req, res) => {
  db.query(
    `SELECT kp.id, kp.klus_id, kp.uren_id, kp.product_id, p.naam, p.artikelcode,
       kp.aantal, kp.prijs_per_stuk, p.eenheid
     FROM klus_producten kp
     JOIN producten p ON kp.product_id = p.id
     WHERE kp.klus_id = ? AND kp.uren_id IS NULL
     ORDER BY kp.aangemaakt_op DESC`,
    [parseInt(req.params.id)],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json(rows);
    });
});

// Producten per uren-entry (dag-specifiek)
app.get('/api/uren/:id/producten', requireMedewerker, (req, res) => {
  db.query(
    `SELECT kp.id, kp.klus_id, kp.uren_id, kp.product_id, p.naam, p.artikelcode,
       kp.aantal, kp.prijs_per_stuk, p.eenheid
     FROM klus_producten kp
     JOIN producten p ON kp.product_id = p.id
     WHERE kp.uren_id = ?
     ORDER BY kp.aangemaakt_op DESC`,
    [parseInt(req.params.id)],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json(rows);
    });
});

app.post('/api/klussen/:id/producten', requireMedewerker, (req, res) => {
  const { product_id, aantal, prijs_per_stuk, uren_id } = req.body;
  if (!product_id || !aantal) return res.status(400).json({ error: 'Product en aantal zijn verplicht' });
  db.query(
    'INSERT INTO klus_producten (klus_id, uren_id, product_id, aantal, prijs_per_stuk) VALUES (?,?,?,?,?)',
    [parseInt(req.params.id), uren_id ? parseInt(uren_id) : null, parseInt(product_id), parseFloat(aantal), prijs_per_stuk != null ? parseFloat(prijs_per_stuk) : null],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ id: result.insertId });
    });
});

app.put('/api/klus-producten/:id', requireMedewerker, (req, res) => {
  const { aantal } = req.body;
  if (!aantal) return res.status(400).json({ error: 'Aantal is verplicht' });
  db.query('UPDATE klus_producten SET aantal=? WHERE id=?',
    [parseFloat(aantal), parseInt(req.params.id)],
    (err) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ ok: true });
    });
});

app.delete('/api/klus-producten/:id', requireMedewerker, (req, res) => {
  db.query('DELETE FROM klus_producten WHERE id=?', [parseInt(req.params.id)], (err) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json({ ok: true });
  });
});


app.get('/api/slider', (req, res) => {
  db.query('SELECT id, bestandsnaam, titel, volgorde FROM slider_afbeeldingen WHERE actief=1 ORDER BY volgorde, id', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB fout' });
    res.json(rows);
  });
});

app.post('/api/slider', requireAdmin, sliderUpload.single('afbeelding'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Geen afbeelding' });
  const { titel = '', volgorde = 0 } = req.body;
  db.query('INSERT INTO slider_afbeeldingen (bestandsnaam, titel, volgorde) VALUES (?,?,?)',
    [req.file.filename, titel, parseInt(volgorde) || 0],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'DB fout' });
      res.json({ id: result.insertId, bestandsnaam: req.file.filename });
    });
});

app.delete('/api/slider/:id', requireAdmin, (req, res) => {
  db.query('SELECT bestandsnaam FROM slider_afbeeldingen WHERE id=?', [req.params.id], (err, rows) => {
    if (err || !rows.length) return res.status(404).json({ error: 'Niet gevonden' });
    const bestand = path.join(__dirname, 'public', 'slider', rows[0].bestandsnaam);
    db.query('DELETE FROM slider_afbeeldingen WHERE id=?', [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'DB fout' });
      fs.unlink(bestand, () => {});
      res.json({ ok: true });
    });
  });
});

// ---- WERKZAAMHEDEN ----
app.get('/api/werkzaamheden', (req, res) => {
  db.query('SELECT id, titel, tekst, afbeelding, sort_order FROM werkzaamheden ORDER BY sort_order, id', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(rows);
  });
});

app.post('/api/werkzaamheden', requireAdmin, werkzaamhedenUpload.single('afbeelding'), (req, res) => {
  const { titel, tekst, sort_order } = req.body;
  if (!titel) return res.status(400).json({ error: 'Titel verplicht' });
  const afbeelding = req.file ? '/werkzaamheden/' + req.file.filename : null;
  db.query('INSERT INTO werkzaamheden (titel, tekst, afbeelding, sort_order) VALUES (?,?,?,?)',
    [titel.trim(), tekst || '', afbeelding, parseInt(sort_order) || 0],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ id: result.insertId });
    });
});

app.put('/api/werkzaamheden/:id', requireAdmin, werkzaamhedenUpload.single('afbeelding'), (req, res) => {
  const id = parseInt(req.params.id);
  const { titel, tekst, sort_order } = req.body;
  if (!titel) return res.status(400).json({ error: 'Titel verplicht' });
  if (req.file) {
    // Nieuwe afbeelding: verwijder oude
    db.query('SELECT afbeelding FROM werkzaamheden WHERE id = ?', [id], (err, rows) => {
      if (rows && rows[0] && rows[0].afbeelding) {
        const oud = path.join(__dirname, 'public', rows[0].afbeelding);
        require('fs').unlink(oud, () => {});
      }
      const afbeelding = '/werkzaamheden/' + req.file.filename;
      db.query('UPDATE werkzaamheden SET titel=?, tekst=?, afbeelding=?, sort_order=? WHERE id=?',
        [titel.trim(), tekst || '', afbeelding, parseInt(sort_order) || 0, id],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'Database fout' });
          res.json({ ok: true });
        });
    });
  } else {
    db.query('UPDATE werkzaamheden SET titel=?, tekst=?, sort_order=? WHERE id=?',
      [titel.trim(), tekst || '', parseInt(sort_order) || 0, id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database fout' });
        res.json({ ok: true });
      });
  }
});

app.delete('/api/werkzaamheden/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  db.query('SELECT afbeelding FROM werkzaamheden WHERE id = ?', [id], (err, rows) => {
    if (rows && rows[0] && rows[0].afbeelding) {
      const bestand = path.join(__dirname, 'public', rows[0].afbeelding);
      require('fs').unlink(bestand, () => {});
    }
    db.query('DELETE FROM werkzaamheden WHERE id = ?', [id], (err2) => {
      if (err2) return res.status(500).json({ error: 'Database fout' });
      res.json({ ok: true });
    });
  });
});

// ---- SERVICES ----
app.get('/api/services', (req, res) => {
  db.query('SELECT id, titel, tekst, afbeelding, sort_order FROM services ORDER BY sort_order, id', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json(rows);
  });
});

app.post('/api/services', requireAdmin, servicesUpload.single('afbeelding'), (req, res) => {
  const { titel, tekst, sort_order } = req.body;
  if (!titel) return res.status(400).json({ error: 'Titel verplicht' });
  const afbeelding = req.file ? '/services/' + req.file.filename : null;
  db.query('INSERT INTO services (titel, tekst, afbeelding, sort_order) VALUES (?,?,?,?)',
    [titel.trim(), tekst || '', afbeelding, parseInt(sort_order) || 0],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ id: result.insertId });
    });
});

app.put('/api/services/:id', requireAdmin, servicesUpload.single('afbeelding'), (req, res) => {
  const id = parseInt(req.params.id);
  const { titel, tekst, sort_order } = req.body;
  if (!titel) return res.status(400).json({ error: 'Titel verplicht' });
  if (req.file) {
    db.query('SELECT afbeelding FROM services WHERE id = ?', [id], (err, rows) => {
      if (rows && rows[0] && rows[0].afbeelding) {
        const oud = path.join(__dirname, 'public', rows[0].afbeelding);
        require('fs').unlink(oud, () => {});
      }
      const afbeelding = '/services/' + req.file.filename;
      db.query('UPDATE services SET titel=?, tekst=?, afbeelding=?, sort_order=? WHERE id=?',
        [titel.trim(), tekst || '', afbeelding, parseInt(sort_order) || 0, id],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'Database fout' });
          res.json({ ok: true });
        });
    });
  } else {
    db.query('UPDATE services SET titel=?, tekst=?, sort_order=? WHERE id=?',
      [titel.trim(), tekst || '', parseInt(sort_order) || 0, id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database fout' });
        res.json({ ok: true });
      });
  }
});

app.delete('/api/services/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  db.query('SELECT afbeelding FROM services WHERE id = ?', [id], (err, rows) => {
    if (rows && rows[0] && rows[0].afbeelding) {
      const bestand = path.join(__dirname, 'public', rows[0].afbeelding);
      require('fs').unlink(bestand, () => {});
    }
    db.query('DELETE FROM services WHERE id = ?', [id], (err2) => {
      if (err2) return res.status(500).json({ error: 'Database fout' });
      res.json({ ok: true });
    });
  });
});


// --- API: maandaanbiedingen ---
// Publiek: ophalen voor een maand (standaard huidige maand)
app.get('/api/aanbiedingen', (req, res) => {
  const nu = new Date();
  const jaar = parseInt(req.query.jaar) || nu.getFullYear();
  const maand = parseInt(req.query.maand) || (nu.getMonth() + 1);
  const aanbParams = [jaar, maand];
  let aanbBezorgWhere = '';
  if (req.query.bezorging) {
    const bv = req.query.bezorging.trim();
    if (bv === 'afhaal') {
      // Afhalen = geen beperking, alles tonen
    } else if (bv === 'zelf') {
      aanbBezorgWhere = " AND p.bezorging IN ('zelf', 'post')";
    } else if (bv === 'post') {
      aanbBezorgWhere = " AND p.bezorging = 'post'";
    }
  }
  db.query(
    `SELECT ma.id, ma.jaar, ma.maand, ma.korting_procent, ma.korting_prijs,
            p.id AS product_id, p.naam, p.artikelcode, p.prijs AS originele_prijs, p.eenheid, p.bezorging,
            (SELECT bestandsnaam FROM product_afbeeldingen WHERE product_id = p.id ORDER BY volgorde, id LIMIT 1) AS afbeelding
     FROM maandaanbiedingen ma
     JOIN producten p ON p.id = ma.product_id
     WHERE ma.jaar = ? AND ma.maand = ? AND p.verwijderd_op IS NULL AND p.actief = 1${aanbBezorgWhere}
     ORDER BY ma.id`,
    aanbParams,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(rows);
    }
  );
});

// Admin: beschikbare maanden (welke maanden hebben al aanbiedingen)
app.get('/api/aanbiedingen/maanden', requireAdmin, (req, res) => {
  db.query(
    `SELECT jaar, maand, COUNT(*) AS aantal FROM maandaanbiedingen GROUP BY jaar, maand ORDER BY jaar DESC, maand DESC`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json(rows);
    }
  );
});

// Admin: toevoegen product aan maand
app.post('/api/aanbiedingen', requireAdmin, (req, res) => {
  const { jaar, maand, product_id, korting_procent, korting_prijs } = req.body;
  if (!jaar || !maand || !product_id) return res.status(400).json({ error: 'jaar, maand en product_id zijn verplicht' });
  db.query(
    `INSERT INTO maandaanbiedingen (jaar, maand, product_id, korting_procent, korting_prijs) VALUES (?,?,?,?,?)
     ON DUPLICATE KEY UPDATE korting_procent=VALUES(korting_procent), korting_prijs=VALUES(korting_prijs)`,
    [jaar, maand, product_id, korting_procent || null, korting_prijs || null],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ ok: true });
    }
  );
});

// Admin: bijwerken korting van een aanbieding
app.put('/api/aanbiedingen/:id', requireAdmin, (req, res) => {
  const { korting_procent, korting_prijs } = req.body;
  db.query(
    `UPDATE maandaanbiedingen SET korting_procent=?, korting_prijs=? WHERE id=?`,
    [korting_procent || null, korting_prijs || null, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database fout' });
      res.json({ ok: true });
    }
  );
});

// Admin: verwijderen product uit maand
app.delete('/api/aanbiedingen/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM maandaanbiedingen WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database fout' });
    res.json({ ok: true });
  });
});

app.listen(3000, () => {
  console.log('Server draait op poort 3000');
});
