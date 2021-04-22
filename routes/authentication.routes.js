const express = require('express');
const router = express.Router();
const User = require('../models/User.model');
const bcrypt = require('bcryptjs');

router.get('/signup', (req, res) => {
    res.render('authentication/authentic');
});

router.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    //check user and pass
    if(username === '' ||  password === '') {
        res.render('authentication/authentic', {
            errorMessage: 'User and Password needed'
        })
        return;
    }

    //check if user exists
    const user = await User.findOne({username: username});

    if(user !== null) {
        res.render('authentication/authentic',
        { errorMessage: 'Username already exists'})
        return;
    }

    const saltRounds = 10;
    const salt = bcrypt.genSaltSync(saltRounds);
    const hashedPassword = bcrypt.hashSync(password, salt);

    await User.create({
        username,
        password: hashedPassword
    });
    res.redirect('/');
});

router.get('/login', (req, res) => {
    res.render('authentication/login');
});

router.post('/login', async (req, res) => {
    const { username, password} = req.body;

    if(username === '' || password === '') {
        res.render('authentication/login',
        {errorMessage: 'Username and password needed'})
        return;
    }

    const user = await User.findOne({username: username});
    if(user === null) {
        res.render('authentication/login',
        {errorMessage: 'Invalid'});
        return;
    }

    if(bcrypt.compareSync(password, user.password)) {
        console.log('Login -> Success');
        req.session.currentUser = user;
        res.redirect('/')
    }
    else {
        res.render('authentication/login',
        { errorMessage: 'Wrong password' })
        return;
    }
});


module.exports = router;