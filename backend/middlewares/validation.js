const { body, param, validationResult } = require('express-validator');

// Middleware pour gérer les erreurs de validation
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Données invalides', details: errors.array() });
  }
  next();
};

// Validation pour l'inscription
const validateRegister = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Le nom d\'utilisateur doit contenir entre 3 et 50 caractères')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres et underscores'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Email invalide')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Le mot de passe doit contenir au moins 6 caractères'),
  handleValidationErrors
];

// Validation pour la connexion
const validateLogin = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Email invalide')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Le mot de passe est requis'),
  handleValidationErrors
];

// Validation pour les articles
const validateArticle = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Le titre doit contenir entre 1 et 255 caractères'),
  body('content')
    .trim()
    .notEmpty()
    .withMessage('Le contenu est requis'),
  body('author_id')
    .isInt({ min: 1 })
    .withMessage('author_id doit être un entier positif'),
  handleValidationErrors
];

// Validation pour la recherche d'articles
const validateSearch = [
  body('title')
    .trim()
    .isLength({ max: 100 })
    .withMessage('La recherche ne peut pas dépasser 100 caractères')
    .custom((value) => {
      // Rejeter les caractères SQL dangereux
      if (/['";\\--]/.test(value)) {
        throw new Error('Caractères invalides dans la recherche');
      }
      return true;
    }),
  handleValidationErrors
];

// Validation pour les IDs de paramètres
const validateId = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('ID invalide'),
  handleValidationErrors
];

// Validation pour la modification d'utilisateur
const validateUserUpdate = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('ID invalide'),
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Le nom d\'utilisateur doit contenir entre 3 et 50 caractères'),
  body('email')
    .optional()
    .trim()
    .isEmail()
    .withMessage('Email invalide')
    .normalizeEmail(),
  body('password')
    .optional()
    .isLength({ min: 6 })
    .withMessage('Le mot de passe doit contenir au moins 6 caractères'),
  body('role')
    .optional()
    .isIn(['user', 'admin'])
    .withMessage('Le rôle doit être "user" ou "admin"'),
  handleValidationErrors
];

module.exports = {
  validateRegister,
  validateLogin,
  validateArticle,
  validateSearch,
  validateId,
  validateUserUpdate
};
