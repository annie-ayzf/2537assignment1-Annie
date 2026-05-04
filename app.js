require('./utils.js');
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();
app.use(express.static(__dirname + '/public'));

const Joi = require('joi');
const mongoSanitize = require('express-mongo-sanitize');

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; // expire after 1 hour

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
    ttl: 60 * 60;
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


//routes
app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href='/members'><button>Go to Members Area</button></a>
            <a href='/logout'><button>Logout</button></a>
        `)
    } else {
        res.send(`
            <a href="/signup"> <button> Sign Up </button></a>
            <br>
            <a href="/login"> <button> Log In </button></a>
        `);
    }
    
});

//sign up page
app.get('/signup', (req, res) => {
    if(req.session.authenticated){
        res.redirect('/members');
        return;
    } else {
        var html = `
            create user
            <form action='/signupping' method='post'>
            <input name='name' type='text' placeholder='name'>
            <input name='email' type='email' placeholder='email'>
            <input name='password' type='password' placeholder='password'>
            <button>Submit</button>
            </form>
        `;
        res.send(html);

    }
   
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

    await userCollection.insertOne({name: name, email: email, password: hashedPassword});

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
    console.log("Inserted user");

});


//login page
app.get('/login', (req, res) => {
    if(req.session.authenticated){
        res.redirect("/members");
        return;
    } else {
        var html = `
            log in
            <form action='/loggingin' method='post'>
            <input name='email' type='email' placeholder='email'>
            <input name='password' type='password' placeholder='password'>
            <button>Submit</button>
            </form>
        `;

        res.send(html);
    }
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

    const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1, _id: 1}).toArray();

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
app.get('/members', (req, res) => {
    if(req.session.authenticated){
        const name = req.session.name;

        //random images
        const images = ['image1.webp', 'image2.jpg', 'image3.avif'];
        const randomImage = images[Math.floor(Math.random() * images.length)];

        var html = `
            <h1>Hello, ${name}.</h1>
            <img src="/${randomImage}" width="300">
            <br>
            <a href='/logout'><button>Sign out</button></a>
        `;
        res.send(html);

    } else {
        res.redirect('/');
    }
    

});

//log out
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


//404
app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})



app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});