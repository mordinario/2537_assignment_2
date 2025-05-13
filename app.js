/*
Goals:
- EJS
- Authorization
- Bootstrap

- As a user, I want the website to have a consistent look and feel.
- As a user, I want the website to have a logical flow.
- As a user, I want the website to be aesthetically pleasing.
- As a user, I want the website to look good on my mobile phone and on my desktop computer.
- As an administrator of the site, I want to be able to see all the users and which type they are.
- As an administrator of the site, I want to be able to promote users that I trust admin privileges
  and demote users if I don't.
- As an administrator of the site, I want to make sure only admins can see the admin page.

- As a developer, I want to have a code base that is easy to read and to maintain.
- As a developer, I want to minimize the amount times I copy/paste the same or similar code.
- As a developer, I want to avoid editing the same file as my teammates to avoid git merge
  conflicts.
- As a developer, I want to avoid large code files (with lots of lines) – instead I prefer several,
  smaller code files.
*/

// Three things:
// - dependencies
// - port
// - app

// ----- Dependencies -----
// (also installed with "npm i ___")
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const fs = require('fs');
const Joi = require('joi');
require('dotenv').config();
require('./utils.js');

// ----- Port -----
// (pick the first if it exists,
//  pick the second if it doesn't)
const port = process.env.PORT || 3000;

// ----- App -----
const app = express();
app.set('view engine', 'ejs');

// Pick amount of hash rounds to
// hash the passwords
const saltRounds = 12;

// Pick how many milliseconds it takes for
// the session to expire
// (hours * minutes * seconds * milliseconds)
const expireTimeMs = 60 * 60 * 1000;

// Create secret session information
const mongodb_host              = process.env.MONGODB_HOST;
const mongodb_user              = process.env.MONGODB_USER;
const mongodb_password          = process.env.MONGODB_PASSWORD;
const mongodb_database          = process.env.MONGODB_DATABASE;
const node_session_secret       = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret    = process.env.MONGODB_SESSION_SECRET;

// Get users from database
// (taken from COMP2537 example)
var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');
// Set default perms
var userStatus = "user";

// Create connection to database(? i think this is what this does)
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

// Copied from COMP 2537
app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false, 
    resave: true
}));

// allows req.body parsing
app.use(express.urlencoded({extended: false}));
// Sets root folder
app.use(express.static(__dirname + "/public"));

// Checks for authentication
async function redirectIfAuth(req, res, next)
{
    if(req.session.authenticated)
    {
        res.redirect('/members');
    }
    else
    {
        next();
    }
}

// Checks for authentication
async function redirectIfNoAuth(req, res, next)
{
    if(!req.session.authenticated)
    {
        res.redirect('/login');
    }
    else
    {
        next();
    }
}

// Returns true if a given email is
// in the "database", else false
async function inDatabase(email)
{
    const result = await userCollection.find({email: email})
                                       .project({name: 1, email: 1, password: 1, _id: 1})
                                       .toArray();
    if(result.length != 1)
    {
        return false;
    }
    else
    {
        return true;
    }
}

// Returns true if a given password
// matches the given email, else false
async function validPassword(email, password)
{
    const result = await userCollection.find({email: email})
                                       .project({name: 1, email: 1, password: 1, _id: 1})
                                       .toArray();
    if(result.length != 1)
    {
        return false;
    }
    if (await bcrypt.compare(password, result[0].password))
    {
        return true;
    }
}

// Logs in a user and redirects them to
// the main page
function redirectLoggedInUser(req, res)
{
    req.session.authenticated = true;
    req.session.name = req.body.name;
    req.session.cookie.maxAge = expireTimeMs;
    res.redirect('/members');
}

// Redirects if a person doesn't have
// authorization
async function validateAuthorization(req, res, next)
{
    const result = await userCollection.find({email: req.session.email})
                                       .toArray();
    const user = result[0];
    if(user.status == "admin")
    {
        next();
    }
    else
    {
        res.redirect("/admin");
    }
}

async function getUserStatus(req, res, next)
{
    const result = await userCollection.find({email: req.session.email})
                                       .toArray();
    const user = result[0];
    if(user) {
        userStatus = user.status;
    }
    else
    {
        userStatus = "user";
    }
    next();
}

// App stuff
app.get('/', getUserStatus, (req,res) => {
    res.render('main', {
        title: "Main Page",
        auth: req.session.authenticated || "None",
        status: userStatus
    });
});

app.get('/signup', getUserStatus, (req,res) => {
    let error = req.session.validationError;
    req.session.validationError = "";
    res.render("signup", {
        title: "Sign Up",
        error: error,
        auth: req.session.authenticated || "None",
        status: userStatus
    });
});

app.get('/login', redirectIfAuth, getUserStatus, (req,res) => {
    let error = req.session.validationError;
    req.session.validationError = "";
    res.render("login", {
        title: "Log In",
        error: error,
        auth: req.session.authenticated || "None",
        status: userStatus
    });
});

app.get('/members', redirectIfNoAuth, getUserStatus, (req,res) => {
    res.render("members", {
        title: "Main Page",
        name: req.session.name || 'user',
        auth: req.session.authenticated || "None",
        status: userStatus,
        js: ["js/members.js"]
    });
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/admin', redirectIfNoAuth, getUserStatus, async (req,res) => {
    const result = await userCollection.find({email: req.session.email})
                                       .toArray();
    const user = result[0];
    var collect = await userCollection.find().toArray();
    if(user.status != "admin") res.status(403);
    res.render("admin", {
        title: "Admin Page",
        users: collect,
        auth: req.session.authenticated || "None",
        status: user.status || "user"
    })
});

app.get('/dne', getUserStatus, (req,res) => {
    res.status(404).render("dne", {
        title: "404 - Page Does Not Exist",
        auth: req.session.authenticated || "None",
        status: userStatus
    });
});

// add user to "database"
// (or redirect if user exists)
// (taken from 2537)
app.post('/addUser', async (req,res) => {
    // Get name, email, and password
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;
    // Reset validation error string
    req.session.validationError = "";

    // If email not in database,
    // add name, email, and password
    if(!await inDatabase(email))
    {
        // Set rules for name, email and password
        const nameSchema = Joi.string().alphanum().max(20).required();
        const emailSchema = Joi.string().email({tlds: {allow: false}}).required();
        const passwordSchema = Joi.string().max(20).required();
        // Validate name, email and password
        const nameValidation = nameSchema.validate(name);
        const emailValidation = emailSchema.validate(email);
        const passwordValidation = passwordSchema.validate(password);
        let error = false;
        // If name, email or password are invalid,
        // log error and redirect
        if(nameValidation.error != null)
        {
            req.session.validationError += "Invalid name (either missing, not exclusively alphanumeric characters, or greater than 20 characters)</p><p>";
            error = true;
        }
        if(emailValidation.error != null)
        {
            req.session.validationError += "Invalid email (either missing or invalid email)</p><p>";
            error = true;
        }
        if(passwordValidation.error != null)
        {
            req.session.validationError += "Invalid password (either missing, not exclusively alphanumeric characters, or greater than 20 characters)</p><p>";
            error = true;
        }
        if(error == true)
        {
            res.redirect('/signup');
            return;
        }
        // Else, add user
        var hashedPassword = await bcrypt.hash(password, saltRounds);
        await userCollection.insertOne({name: name, email: email, password: hashedPassword, status: "user"});
        req.session.email = email;
        redirectLoggedInUser(req, res);
    }
    // Else, email already in database
    // Redirect user to login page
    else
    {
        req.session.validationError += "Email already registered. Sign up with a new one, or try to login.";
        res.redirect('/signup');
    }
});

// Attempt to log in user
app.post('/loginUser', async (req,res) => {
    // Get email and password
    var email = req.body.email;
    var password = req.body.password;
    req.session.validationError = "";
    // Set rules for email
    const schema = Joi.string().email({tlds: {allow: false}}).required();
    // Validate email
    const validationResult = schema.validate(email);
    // If email is invalid,
    // log error and redirect
    if(validationResult.error != null)
    {
        req.session.validationError += "Invalid email.";
        res.redirect('/login');
    }
    // Else, email is valid
    else
    {
        // If email not in database,
        // // redirect to signup page
        if(!await inDatabase(email))
        {
            req.session.validationError += "Email not registered. Sign up first.";
            res.redirect('/login');
        }
        // Else, if valid credentials, log user in
        else
        {
            if(await validPassword(email, password))
            {
                // Get name from database
                userAsArray = await userCollection.find({email: email}).toArray();
                req.body.name = userAsArray[0].name;
                req.session.email = userAsArray[0].email;
                userStatus = userAsArray[0].status;
                redirectLoggedInUser(req, res);
            }
            // Else, redirect to login page
            else
            {
                req.session.validationError += "Incorrect password for this email.";
                res.redirect('/login');
            }
        }
    }
});

// Update user entry in database
app.get('/updateUser', validateAuthorization, getUserStatus, async (req,res) => {
    // Get email and status
    let email = req.query.user;
    let status = req.query.status;
    // Update database
    await userCollection.updateOne({email: email}, {$set: {status: status}});
    // Redirect after finished
    res.redirect("/admin");
});

// At end of file
// (taken from express docs)
app.use((req, res) => {
    res.status(404).redirect('/dne');
});

// Listen
app.listen(port, () => {
    console.log("heyyy check out port " + port);
});