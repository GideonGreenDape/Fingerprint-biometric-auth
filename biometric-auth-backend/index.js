const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const { isoUint8Array } = require('@simplewebauthn/server/helpers');
const NodeCache = require('node-cache');
const myCache = new NodeCache();

const app = express();
app.use(session({
    secret: 'your-secret-key', // Replace with a secure key
    resave: false,
    saveUninitialized: true
}));
  
app.use(bodyParser.json());
app.use(cors());

// Set up MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'biometric_auth'
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err.stack);
   // return;
  }
  console.log('Connected to database.');
});

// Helper functions
const getUserByUsername = (username, callback) => {
  db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
    if (err) {
      console.error(err);
      callback(err, null);
    } else {
      callback(null, results[0]);
    }
  });
};

const getCredentialsByUserId = (userId, callback) => {
  db.query("SELECT * FROM biometric_credentials WHERE user_id = ?", [userId], (err, results) => {
    if (err) {
      console.error(err);
      callback(err, null);
    } else {
      callback(null, results);
    }
  });
};

const saveUser = (username, passwordHash, name, callback) => {
  db.query("INSERT INTO users (username, password_hash, name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)", [username, passwordHash, name], (err, results) => {
    if (err) {
      console.error(err);
      callback(err);
    } else {
      callback(null, results.insertId);
    }
  });
};

const saveCredential = (userId, credential, callback) => {
  const { credential_id, public_key, webAuthnUserID, counter, deviceType, backedUp , transport} = credential;

  const publicKeyBuffer = Buffer.from(public_key);
  const transportString = JSON.stringify(transport);
  const query = `
    INSERT INTO biometric_credentials 
    (user_id, credential_id, counter, public_key, webAuthnUserID, deviceType, backedUp, transports)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
    counter = VALUES(counter), 
    public_key = VALUES(public_key),
    webAuthnUserID = VALUES(webAuthnUserID),
    deviceType = VALUES(deviceType),
    backedUp = VALUES(backedUp),
    transports = VALUES(transports)
  `;

  db.query(query, 
    [userId, credential_id, counter, publicKeyBuffer, webAuthnUserID, deviceType, backedUp , transportString], (err) => {
    if (err) {
      console.error(err);
      callback(err);
    } else {
      callback(null);
    }
  });
};

// Register a user
app.post('/api/register', async (req, res) => {
  const { username, password, name } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);
  saveUser(username, passwordHash, name, (err, userId) => {
    if (err) return res.status(500).json({ error: 'Failed to register user' });
    res.json({ success: true, userId });
  });
});

// Authenticate using username/password
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  getUserByUsername(username, async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid username or password' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid username or password' });

    // Generate JWT token
    const token = jwt.sign({ userId: user.id, username: user.username , name: user.name}, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ success: true, token });
  });
});

// Register WebAuthn credential options
app.post('/api/biometric/register-options', async(req, res) => {
  const { username } = req.body;

  //getUserByUsername(username, async(err, user) => {
  //  if (err || !user) return res.status(400).json({ error: 'User not found' });

    //const userID = isoUint8Array.fromUTF8String(user.id.toString()); // Convert user ID to Uint8Array
    const userID = isoUint8Array.fromUTF8String("1");
    const registrationOptions = await generateRegistrationOptions({
      rpName: 'Biometric Login App',
      rpID: 'pwa-biometric-login.vercel.app',
      userID: userID,
      userName: username,
      timeout: 60000,
      attestationType: 'none', // Adjust based on your needs
    });

    if (!registrationOptions.challenge) {
        return res.status(500).json({ error: 'Failed to generate challenge' });
      }

    // Save challenge in session or database (for verification later)
    myCache.set(userID.toString(), registrationOptions.challenge);
    myCache.set("webauthuserid" +userID.toString() , registrationOptions.user.id);

    res.json(registrationOptions);
 // });
});

// Register WebAuthn credential
app.post('/api/biometric/register', (req, res) => {
  const { credential, username } = req.body;
  getUserByUsername(username, async(err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User not found' });

    const userID = isoUint8Array.fromUTF8String(user.id.toString());
    const webAuthnUserID = myCache.get("webauthuserid" + userID.toString())
    const storedChallenge = myCache.get(userID.toString())

    try {
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: storedChallenge,
        expectedOrigin: 'https://pwa-biometric-login.vercel.app',
        expectedRPID: 'pwa-biometric-login.vercel.app',
      });

      if (verification.verified) {
        const { registrationInfo } = verification;
        const {
        credentialID,
        credentialPublicKey,
        counter,
        credentialDeviceType,
        credentialBackedUp,
        } = registrationInfo;

        saveCredential(user.id, {
          credential_id: credentialID,
          public_key: credentialPublicKey,
          webAuthnUserID,
          counter,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          transport: credential.response.transports
        }, (err) => {
          if (err) return res.status(500).json({ error: 'Failed to save credential' });
          res.json({ success: true });
        });
      } else {
        res.status(400).json({ success: false });
      }
    } catch (error) {
      res.status(400).json({ success: false, error: error.message });
    }
  });
});

// Authenticate WebAuthn credential options
app.post('/api/biometric/authenticate-options', (req, res) => {
  const { username } = req.body;

  getUserByUsername(username, (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User not found' });

    getCredentialsByUserId(user.id, async(err, credentials) => {
      if (err || !credentials.length) return res.status(400).json({ error: 'No credentials found' });

      const userID = isoUint8Array.fromUTF8String(user.id.toString());

      const authenticationOptions = await generateAuthenticationOptions({
        rpID: 'pwa-biometric-login.vercel.app',
        allowCredentials: credentials.map(cred => ({
          id: cred.credential_id,
          transports: JSON.parse(cred.transports),
        })),
        timeout: 60000,
      });
      console.log(authenticationOptions)
      myCache.set(userID.toString(), authenticationOptions.challenge);

      res.json(authenticationOptions);
    });
  });
});

// Authenticate WebAuthn credential
app.post('/api/biometric/authenticate', (req, res) => {
  const { username, credential } = req.body;
  getUserByUsername(username, (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User not found' });

    getCredentialsByUserId(user.id, async(err, credentials) => {
      if (err || !credentials.length) return res.status(400).json({ error: `Could not find passkey ${credential.id} for user ${username}` });

      const userID = isoUint8Array.fromUTF8String(user.id.toString());
      const storedChallenge = myCache.get(userID.toString())

      try {
        const foundCredential = credentials.find(
          cred => cred.user_id === user.id && cred.credential_id === credential.id
        );

        console.log(foundCredential);
        const verification = await verifyAuthenticationResponse({
          response: credential,
          expectedChallenge: storedChallenge,
          expectedOrigin: 'https://pwa-biometric-login.vercel.app',
          expectedRPID: 'pwa-biometric-login.vercel.app',
          authenticator: {
            credentialID: foundCredential.credential_id,
            credentialPublicKey: Array.from(foundCredential.public_key),
            counter: foundCredential.counter,
            transports: JSON.parse(foundCredential.transports)
          },
        });

        if (verification.verified) {
          // Generate JWT token
          const token = jwt.sign({ userId: user.id, username: user.username , name:user.name}, 'your_jwt_secret', { expiresIn: '1h' });
          res.json({ success: true, token });
        } else {
          res.status(400).json({ success: false });
        }
      } catch (error) {
        res.status(400).json({ success: false, error: error.message });
      }
    });
  });
});

app.get("/", (req, res) => res.send("Express on Vercel"));

app.listen(3001, () => {
  console.log('Server running on http://localhost:3001');
});

module.exports = app;