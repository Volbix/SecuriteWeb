const crypto = require('crypto');

// Générer un token CSRF
const generateCsrfToken = (req, res, next) => {
  // Générer un token CSRF aléatoire
  const token = crypto.randomBytes(32).toString('hex');
  
  // Stocker le token dans une session (ou cookie httpOnly)
  // Pour simplifier, on utilise un cookie sécurisé
  res.cookie('csrf-token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS uniquement en production
    sameSite: 'strict',
    maxAge: 3600000 // 1 heure
  });
  
  // Ajouter le token dans les headers pour que le frontend puisse le lire
  res.setHeader('X-CSRF-Token', token);
  
  next();
};

// Vérifier le token CSRF
const verifyCsrfToken = (req, res, next) => {
  // Ignorer les méthodes GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  const tokenFromHeader = req.headers['x-csrf-token'];
  const tokenFromCookie = req.cookies['csrf-token'];
  
  // Vérifier que les tokens correspondent (double-submit cookie pattern)
  if (!tokenFromHeader || !tokenFromCookie || tokenFromHeader !== tokenFromCookie) {
    return res.status(403).json({ error: 'Token CSRF invalide ou manquant' });
  }
  
  next();
};

module.exports = {
  generateCsrfToken,
  verifyCsrfToken
};
