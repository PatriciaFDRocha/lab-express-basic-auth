const express = require('express');
const router = express.Router();

function requireLogin(req, res, next) {
    if(req.session.currentUser) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

/* GET home page */
router.get('/', (req, res, next) => res.render('index', { user: req.session.currentUser}));

router.get('/main', requireLogin, (req, res) => res.render('authentication/main'));

router.get('/private', requireLogin, (req, res) => res.render('authentication/private'));

module.exports = router;
