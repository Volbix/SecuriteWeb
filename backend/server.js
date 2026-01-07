const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { generateCsrfToken, verifyCsrfToken } = require('./middlewares/csrfMiddleware');
require('dotenv').config();

const initializeDbConnection = require('./db');

const app = express();

// Configuration de Helmet pour les headers de sécurité
app.use(helmet());

// Configuration CORS avec whitelist
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['http://localhost:3000', 'http://localhost:4000', 'http://127.0.0.1:3000', 'http://127.0.0.1:4000'];

app.use(cors({
  origin: function (origin, callback) {
    // Autoriser les requêtes sans origin (ex: Postman, mobile apps)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Non autorisé par CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(cookieParser());

// Générer un token CSRF pour toutes les requêtes
app.use('/api/', generateCsrfToken);

// Vérifier le token CSRF pour les requêtes modifiantes
app.use('/api/', verifyCsrfToken);

// Rate limiting global
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limite chaque IP à 100 requêtes par fenêtre
  message: 'Trop de requêtes depuis cette IP, veuillez réessayer plus tard.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Rate limiting strict pour la connexion
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limite à 5 tentatives de connexion par IP
  message: 'Trop de tentatives de connexion, veuillez réessayer dans 15 minutes.',
  skipSuccessfulRequests: true,
});
app.use('/api/auth/login', loginLimiter);

const startServer = async () => {
  try {
    // Attente que la base de données soit prête
    const db = await initializeDbConnection();
    console.log('Base de données initialisée avec succès.');

    // Injection de la connexion DB dans les routes
    app.use((req, res, next) => {
      req.db = db; // Ajout de la connexion à l'objet requête
      next();
    });

    // Importation des routes
    const authRoutes = require('./routes/auth');
    const userRoutes = require('./routes/users');
    const articleRoutes = require('./routes/articles');
    const commentRoutes = require('./routes/comments');

    // Utilisation des routes
    app.use('/api/auth', authRoutes);
    app.use('/api/users', userRoutes);
    app.use('/api/articles', articleRoutes);
    app.use('/api/', commentRoutes);

    const PORT = 5100;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

  } catch (error) {
    console.error('Erreur lors de l\'initialisation du serveur :', error);
    process.exit(1); // Arrêt en cas d'erreur critique
  }
};

startServer();