const express = require('express');

const session = require('express-session');

const bodyParser = require('body-parser');

const crypto = require('crypto');

const app = express();

const PORT = 3000;


const users = {};


app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,

    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 60 * 60 * 1000,
    }
}))


function hashPassword(password) {
    const hash = crypto.createHash('sha256');

    hash.update(password);

    return hash.digest('hex');
}


app.post('/signup', (req, res) => {
    const { username, password } = req.body;

    if(!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    if(users[username]) {
        return res.status(409).send('Username has been existed')
    }

    users[username] = hashPassword(password);

    res.status(201).send(`User ${username} created successfully.`);
})


app.get('/login', (req,res) => {
    const { username, password } = req.body;

    if(!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    req.session.user = { username };

    res.send(`Welcomr ${username}`);
})  


app.get()