const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const dotenv = require('dotenv').config();
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');
const async = require('async');
const moment = require('moment');

const dev_db_url = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0-gevd4.azure.mongodb.net/members_only?retryWrites=true&w=majority`
const mongoDb = process.env.MONGODB_URI || dev_db_url;
mongoose.connect(mongoDb, {useUnifiedTopology: true, useNewUrlParser: true});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
    'User',
    {
        first_name: {type: String, required: true},
        last_name: {type:String, required: true},
        username: {type: String, required: true},
        password: {type: String, required: true},
        isAdmin: {type: Boolean, required: true}
    }
)

const Post = mongoose.model(
    'Post',
    {
        title: {type: String, required: true},
        date: {type: Date, default: Date.now},
        author: {type: Schema.Types.ObjectId, ref: 'User'},
        description: {type: String, required: true}
    }
)

passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({username: username}, (err, user) => {
            if(err) {
                return done(err);
            }
            if(!user) {
                return done(null, false, {msg: 'Incorrect username'});
            }
            bcrypt.compare(password, user.password, (err, res) => {
                if(res) {
                    return done(null, user);
                } else {
                    return done(null, false, {msg: 'Incorrect Password'});
                }
            })
        })
    })
)

passport.serializeUser(function(user, done) {
    done(null, user.id);
})

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err,user) {
        done(err, user);
    })
})

const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

app.use(session({ secret: "cats", resave: false, saveUninitialized: true, cookie: {maxAge: 360000} }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '/public')));

// homepage route
app.get('/', (req, res, next) => {
    async.parallel(
        {
            posts: function(callback) {
                Post.find({})
                    .populate('author')
                    .exec(callback)
            }
        }, function(err, results) {
            if(err) {
                return next(err);
            } else {
                res.render('./views/index', {user: req.user, post: results.posts})
            }
        }
    )
})

// sign up route + sign up render / get
app.get('/sign-up', (req, res) => {
    res.render('./views/sign-up-form')
})

// sign up post
app.post('/sign-up', (req, res, next) => {
    bcrypt.hash(req.body.password, 10, (err,hashedPassword) => {
        if(err) {return next(err)}
        else {
            const user = new User(
                {
                    username: req.body.username,
                    password: hashedPassword,
                    first_name: req.body.first_name,
                    last_name: req.body.last_name,
                    isAdmin: false
                }
            ).save((err) => {
                if(err) {
                    return next(err);
                } else {
                    res.redirect('/');
                }
            })
        }
    })
})

// sign up login + get
app.get('/login', (req, res) => {
    res.render('./views/login')
})

// login verify
app.post('/login', passport.authenticate("local", {
    successRedirect: '/',
    failureRedirect: '/login',
}))

app.get('/create-message', (req, res) => {
    res.render('./views/create_message_form', {user: req.user});
})

app.post('/create-message', (req, res, next) => {
    var post = new Post(
        {
            title: req.body.title,
            description: req.body.description,
            author: req.user,
        }
    ).save((err) => {
        if(err) {return next(err)}
        else {
            res.redirect('/');
        }
    })
})

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
})

app.listen(process.env.PORT || 3000, () => {
    console.log('App is listening at port 3000');
})