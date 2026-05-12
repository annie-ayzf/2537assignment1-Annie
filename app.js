require('./utils.js');
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const saltRounds = 12;
const { ObjectId } = require('mongodb');

const app = express();
app.use(express.static(__dirname + '/public'));

const Joi = require('joi');
const mongoSanitize = require('express-mongo-sanitize');

const PORT = process.env.PORT || 3001;
const expireTime = 1 * 60 * 60 * 1000; // expire after 1 hour

//Secret section
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

//load database connection
const {database} = include(`databaseConnection`);
const userCollection = database.db(mongodb_user_database).collection('users');

app.set('view engine', 'ejs');

//express read form data and JSON data from requests.
app.use(express.urlencoded({extended: false}));
app.use(express.json());

//hack for express 5.x not setting req.query as writable
app.use((req, _res, next) => {
	Object.defineProperty(req, 'query', {
		...Object.getOwnPropertyDescriptor(req, 'query'),
		value: req.query,
		writable: true,
	});

	next();
})

app.use(mongoSanitize(
    {replaceWith: '%'}
));

//create a mongoDB place to store session data
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: {
        secret: mongodb_session_secret
    },
    ttl: 60 * 60
});

//turns on session. what allows login to be remembered
app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: expireTime
    }
}
));

//checks if user is logged in
function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

//Creates middleware to protect routes
function sessionValidation(redirectPath) {
    return function(req, res, next) {
        if (isValidSession(req)) {
            next();
        } else {
            res.redirect(redirectPath);
        }
    }
}

//check if it is Admin
function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}


//middleware for admin only pages
function adminAuthroization(req, res, next) {
    if(!isAdmin(req)) {
        res.status(403);
        res.render("errormessage", {error: "Not Authorized - 403"});
        return;
    }
    else {
        next();
    }
}




//routes
app.get('/', (req, res) => {
    res.render("index", {
        authenticated: isValidSession(req),
        name: req.session.name
    });
});

//sign up page
app.get('/signup', (req, res) => {
    if (isValidSession(req)) {
        res.redirect('/members');
        return;
    }
    
    res.render("signup");

});

app.post('/signupping', async (req, res) => {
    if(!req.body.name){
        res.send("Name is required. <br><a href='/signup'>Try again</a>");
        return;
    }

    if(!req.body.email){
        res.send("Email is required. <br><a href='/signup'>Try again</a>");
        return;
    }

    if(!req.body.password){
        res.send("Password is required. <br><a href='/signup'>Try again</a>");
        return;
    }

    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;


    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });
    
    const validationResult = schema.validate({name, email, password});
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword, user_type: 'user'});

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
    console.log("Inserted user");

});

//login page
app.get('/login', (req, res) => {
    if (isValidSession(req)) {
        res.redirect('/members');
        return;
    }

    res.render("login");
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    var name = req.body.name;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);

    if(validationResult.error != null){
        console.log(validationResult.error);
        res.redirect("/login");
    }

    const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1, user_type: 1, _id: 1}).toArray();

    console.log(result);
    if(result.length != 1) {
        res.send("Invalid email/password combination. <br><a href='/login'>Try again</a>");
        return;
    }
    if(await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;

    } else {
        console.log("incorrect password");
        res.send("Invalid email/password combination. <br><a href='/login'>Try again</a>");
        return;
    }
});

//members page
app.get('/members', sessionValidation("/"), (req, res) => {
    const name = req.session.name;

    const images = ['image1.webp', 'image2.jpg', 'image3.avif'];

    res.render('members', {
        name: name,
        images: images
    });

    

});

//admins page
app.get('/admin', sessionValidation("/login"), adminAuthroization, async (req, res) => {
    //get all users from databse
    const result = await userCollection.find().project({name: 1, user_type: 1, _id: 1}).toArray();

    res.render("admin", {users: result});

});

app.post('/promote/:id', sessionValidation("/login"), adminAuthroization, async (req, res) => {
    const userId = req.params.id;

    await userCollection.updateOne(
        { _id: new ObjectId(userId) }, //means find the document where _id equlas this object
        { $set: { user_type: "admin" } }
    )

    res.redirect('/admin');
});

app.post('/demote/:id', sessionValidation("/login"), adminAuthroization, async (req, res) => {
    const userId = req.params.id;

    await userCollection.updateOne(
        { _id: new ObjectId(userId) },
        {$set: { user_type: "user" } }
    )

    res.redirect('/admin');
});

//log out
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


//404
app.use((req, res) => {
    res.status(404);
    res.render("404");
})



app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});