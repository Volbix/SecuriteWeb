const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');
const { validateUserUpdate, validateId } = require('../middlewares/validation');

// Route pour lister les utilisateurs - RÉSERVÉE AUX ADMINS
router.get('/', authenticate, authorizeAdmin, async (req, res) => {
  const sql = 'SELECT id, username, email, role FROM users';
  try {
    const [results] = await req.db.execute(sql);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs' });
  }
});

// Route pour récupérer un utilisateur spécifique - PROTÉGÉE
router.get('/:id', authenticate, validateId, async (req, res) => {
  const { id } = req.params;
  
  // Vérifier que l'utilisateur ne peut voir que ses infos ou est admin
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  const sql = 'SELECT id, username, email, role FROM users WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'utilisateur' });
  }
});

// Route pour supprimer un utilisateur - PROTÉGÉE
router.delete('/:id', authenticate, validateId, async (req, res) => {
  const { id } = req.params;
  
  // Vérifier que l'utilisateur ne peut supprimer que son compte ou est admin
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  const sql = 'DELETE FROM users WHERE id = ?';
  try {
    await req.db.execute(sql, [id]);
    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'utilisateur' });
  }
});

// Route pour modifier un utilisateur - PROTÉGÉE
router.put('/:id', authenticate, validateId, validateUserUpdate, async (req, res) => {
  const { id } = req.params;
  const { username, email, password, role } = req.body;
  
  // Vérifier que l'utilisateur ne peut modifier que son compte ou est admin
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  // Empêcher les utilisateurs non-admin de modifier leur rôle
  let finalRole = role;
  if (req.user.role !== 'admin') {
    // Un utilisateur ne peut pas modifier son rôle
    if (role && role !== req.user.role) {
      return res.status(403).json({ error: 'Vous ne pouvez pas modifier votre rôle' });
    }
    // Garder le rôle original si l'utilisateur n'est pas admin
    finalRole = req.user.role;
  }
  
  // Si l'utilisateur n'est pas admin, empêcher la modification du rôle d'autres utilisateurs
  if (req.user.role !== 'admin' && req.user.id !== parseInt(id)) {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  
  // Récupérer l'utilisateur actuel pour conserver le mot de passe si non modifié
  const sqlSelect = 'SELECT password FROM users WHERE id = ?';
  try {
    const [currentUser] = await req.db.execute(sqlSelect, [id]);
    if (currentUser.length === 0) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    
    // Hasher le nouveau mot de passe si fourni, sinon garder l'ancien
    let hashedPassword = currentUser[0].password;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }
    
    const sql = 'UPDATE users SET username = ?, email = ?, password = ?, role = ? WHERE id = ?';
    await req.db.execute(sql, [username, email, hashedPassword, finalRole, id]);
    const newUser = { id: parseInt(id), username, email, role: finalRole };
    res.json({ message: 'Utilisateur modifié avec succès', user: newUser });
  } catch (err) {
    res.status(500).json({ error: 'Erreur lors de la modification de l\'utilisateur' });
  }
});

module.exports = router;
