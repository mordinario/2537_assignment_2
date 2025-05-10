/*
Goals:
- Simple website
- Node.js + MongoDB
- Express

- If user successfully authenticates
  (correct email and password),
  new session to store the user's info
  - A user is "logged in" if
    they have a valid session
- The encrypted session information is
  stored in a MongoDB session database 
  for 1 hour (and expires after)
  - If a user is not logged in,
    they can't see the members page
- We take in input from the user to
  capture account information and ask
  for log in
  - Properly deal with NoSQL injection
    attacks
- .env file to store encryption secrets
  and MongoDB database credentials
  - DO NOT STORE PASSWORDS IN THE GIT REPO
- Host the site on Render

User stories:
- As a user, I want to be able to 
  sign up for a new account so that 
  I can access the members only area. 
- As a user, I want to be able to
  sign in to my existing account so that
  I can access the members only area. 
- As a user, I want to be able to
  sign out of my account so that 
  nobody else can access it. 
- As a user, I want to see a home page 
  with the options to sign up or sign in
  if I am not currently logged in.
- As a user, I want to see a home page
  welcoming me and showing me the option
  to go to the members only area and sign
  out if I am currently logged in. 
- As a user, I want to be able to see a
  random image when I access the members
  only area so that it is more 
  visually interesting. 
- As a user, I want to be informed if the
  username or password I entered is
  incorrect when signing in so that I can
  correct the mistake.
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
    res.redirect('/loggedin');
}

// App stuff
app.get('/', (req,res) => {
    // how it works in 1537
    let doc = fs.readFileSync("./public/html/main.html", "utf8");
    res.send(doc);
});

app.get('/signup', (req,res) => {
    let doc = fs.readFileSync("./public/html/signup.html", "utf8");
    res.send(doc);
});

app.get('/signupsubmit', (req,res) => {
    let doc = fs.readFileSync("./public/html/signupsubmit.html", "utf8");
    res.send(doc);
});

app.get('/login', (req,res) => {
    if(req.session.authenticated)
        {
            res.redirect('/loggedin');
        }
        else
        {
            let doc = fs.readFileSync("./public/html/login.html", "utf8");
            res.send(doc);
        }
});

app.get('/loginsubmit', (req,res) => {
    let doc = fs.readFileSync("./public/html/loginsubmit.html", "utf8");
    res.send(doc);
});

app.get('/loggedin', (req,res) => {
    if(!req.session.authenticated)
    {
        res.redirect('/');
    }
    else
    {
        let doc = fs.readFileSync("./public/html/loggedin.html", "utf8");
        res.send(doc);
    }
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/dne', (req,res) => {
    let doc = fs.readFileSync("./public/html/dne.html", "utf8");
    res.send(doc);
});

// Gets information needed by some pages
// (I didn't know EJS existed when I did this -
// this is definitely *some* breach of privacy but
// it doesn't need to be perfect anyway)
app.get('/getName', (req,res) => {
    res.json({name: req.session.name || 'User'});
});

app.get('/getError', (req,res) => {
    res.json({error: req.session.validationError});
});

app.get('/getAuth', (req,res) => {
    res.json({auth: req.session.authenticated || 'None'});
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
            req.session.validationError += "Invalid name (either missing, not exclusively alphanumeric characters, or greater than 20 characters)\n";
            error = true;
        }
        if(emailValidation.error != null)
        {
            req.session.validationError += "Invalid email (either missing or invalid email)\n";
            error = true;
        }
        if(passwordValidation.error != null)
        {
            req.session.validationError += "Invalid password (either missing, not exclusively alphanumeric characters, or greater than 20 characters)\n";
            error = true;
        }
        if(error == true)
        {
            res.redirect('/signupsubmit');
            return;
        }
        // Else, add user
        var hashedPassword = await bcrypt.hash(password, saltRounds);
        await userCollection.insertOne({name: name, email: email, password: hashedPassword});
        redirectLoggedInUser(req, res);
    }
    // Else, email already in database
    // Redirect user to login page
    else
    {
        req.session.validationError += "Email already registered. Sign up with a new one, or try to login.";
        res.redirect('/loginsubmit');
        return;
    }
});

// Attempt to log in user
app.post('/loginUser', async (req,res) => {
    // Get email and password
    var email = req.body.email;
    var password = req.body.password;
    req.session.validationError = "";
    // If email not in database,
    // redirect to signup page
    if(!await inDatabase(email))
    {
        req.session.validationError += "Email not registered. Sign up first.";
        res.redirect('/signupsubmit');
    }
    // Else, email in database
    // Set rules for email
    else
    {
        const schema = Joi.string().email({tlds: {allow: false}}).required();
        // Validate email
        const validationResult = schema.validate(email);
        // If email is invalid,
        // log error and redirect
        if(validationResult.error != null)
            {
                req.session.validationError += "Invalid email.";
                res.redirect('/loginsubmit');
            }
        // Else, if valid credentials, log user in
        else
        {
            if(await validPassword(email, password))
                {
                    // Get name from database
                    userAsArray = await userCollection.find({email: email}).toArray();
                    req.body.name = userAsArray[0].name;
                    redirectLoggedInUser(req, res);
                }
                // Else, redirect to login page
                else
                {
                    req.session.validationError += "Incorrect password for this email.";
                    res.redirect('/loginsubmit');
                }
        }
    }
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