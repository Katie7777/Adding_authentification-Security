//import and configure dotevn
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt  = require("mongoose-encryption");//use t0 encrypt password
//const bcrypt = require("bcrypt");//hash password
//const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//initialize session
app.use(session({
  secret:"Our little secret.",
  resave: false,
  saveUninitialized: false
}));

//initialize passport
app.use(passport.initialize());
//use passport to manager the session
app.use(passport.session());


//create database
mongoose.connect("mongodb://localhost:27017/userDB");

//create schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//to hash and salt password and to save users into mongodb database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ["password"]
// });

//create model
const User = new mongoose.model("User", userSchema);

//create local log in strategy
passport.use(User.createStrategy());
//add user identity to the cookie
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});
//break the cookie to authenticate identity
passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});

//when the sign in with google clicked, go to google sign in
app.get("/auth/google", passport.authenticate("google", {scope:['profile']})
);

//redirect user back to our website
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

// app.get("/secrets", function(req,res){
//   if(req.isAuthenticated()){
//     res.render("secrets");
//   }else{
//     res.redirect("/login");
//   }
// });

app.get("/secrets", function(req,res){
  // if(req.isAuthenticated()){
  //   res.render("submit");
  // }else{
  //   res.redirect("/login");
  // }
  //find all secrets that are not null
  User.find({"secrets":{$ne: null}},function(err,foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  });
});

//when logout, only logout our wensite, won't logout google
app.get("/logout",function(req,res){
  req.logout(function(err){
    if(err){
      console.log(err);
    }
  });
  res.redirect("/");
});

//once user registered, create newUser object, save in the database
//render secrets page
app.post("/register", function(req, res) {
  User.register({username: req.body.username}, req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err) {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });


});

//once user login, look for its email in database and check its email
app.post("/login", function(req, res) {
  const user = new User({
    username:req.body.username,
    password:req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });





  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({
  //   email: username
  // }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if (result === true) {
  //           res.render("secrets");
  //         }
  //       });
  //
  //
  //
  //     }
  //   }
  // });
});



app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
