const express = require('express');
const app = express();
const userModel = require('./models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const cookieParser = require('cookie-parser');
const path = require('path');

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.render('index');
});

app.post('/create', async (req, res) => {
    let { username, password, email, age } = req.body;
    try {
        let hash = await bcrypt.hash(password, 10);
        let createdUser = await userModel.create({
            username,
            password: hash, // Store the hashed password
            email,
            age: parseInt(age, 10)
        });
        let token = jwt.sign({ email }, "secretKey"); // Sign the token with a secret key
        res.cookie('token', token);// Set the token in a cookie
        res.send(createdUser);
    } catch (err) {
        res.status(500).send("Error creating user");
    }
});

app.get('/login', async (req, res) => {
    res.render('login');
});


app.post('/login', async function (req, res) {
     let user = await userModel.findOne({ email: req.body.email });
    if (!user) return res.send('User not found');

    // If user exists, compare the provided password with the stored hashed password
    bcrypt.compare(req.body.password, user.password, (err, result) => {
        //console.log(result);
        if (result){
            let token = jwt.sign({email: user.email}, "secretKey"); // Sign the token with a secret key
            res.cookie('token', token); // Set the token in a cookie
            res.send('Login successful');
        }
        else return res.send('Invalid password or email');
});
});

app.get('/logout', (req, res) => {
    res.clearCookie('token'); // Clear the token cookie
    res.redirect('/'); // Redirect to the home page
});



app.listen(3000);