const jwt = require('jsonwebtoken');

// Vérifier que JWT_SECRET est défini au démarrage
if (!process.env.JWT_SECRET) {
  console.error('ERREUR CRITIQUE: JWT_SECRET n\'est pas défini dans les variables d\'environnement!');
  process.exit(1);
}

// Générer un token JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, role: user.role }, // Payload : inclure l'ID utilisateur et son rôle
    process.env.JWT_SECRET, // Clé secrète pour signer le token
    { expiresIn: '12h' } // Expiration du token (ici 3 heures)
  );
};

// Vérifier un token JWT
const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

module.exports = {
  generateToken,
  verifyToken,
};
