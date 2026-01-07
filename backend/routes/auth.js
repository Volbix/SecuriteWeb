const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { generateToken } = require('../utils/jwt');
const { validateRegister, validateLogin } = require('../middlewares/validation');

// Route pour s'inscrire
router.post('/register', validateRegister, async (req, res) => {
  const { username, email, password } = req.body;
  const checkSql = 'SELECT * FROM users WHERE email = ? OR username = ?';
  const insertSql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  try {
    const [existingUsers] = await req.db.execute(checkSql, [email, username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email ou nom d\'utilisateur déjà utilisé' });
    }
    // Hacher le mot de passe avec bcrypt (10 rounds)
    const hashedPassword = await bcrypt.hash(password, 10);
    const [results] = await req.db.execute(insertSql, [username, email, hashedPassword]);
    res.status(201).json({ message: 'Utilisateur créé avec succès', id: results.insertId });
  } catch (err) {
    res.status(500).json({ error: 'Erreur lors de l\'inscription' });
  }
});

// Route pour se connecter
router.post('/login', validateLogin, async (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';
  try {
    const [results] = await req.db.execute(sql, [email]);
    if (results.length === 0) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }
    const user = results[0];
    // Comparer le mot de passe avec bcrypt
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }
    const token = generateToken(user);
    // Ne pas envoyer le mot de passe dans la réponse
    const { password: _, ...userWithoutPassword } = user;
    res.json({ message: 'Connexion réussie', token, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

module.exports = router;
