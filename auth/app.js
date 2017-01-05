var bodyParser = require('body-parser');
var session = require('client-sessions');
var express = require('express');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var csrf = require('csurf');

//https://www.youtube.com/watch?v=yvviEA1pOXw
//Everything You Ever Wanted To Know About Authentication in Node.js
//https://speakerdeck.com/rdegges/everything-you-ever-wanted-to-know-about-authentication-in-node-dot-js
//https://github.com/rdegges/svcc-auth/

var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

var User = mongoose.model('User', new Schema({
  id: ObjectId,
  firstName: String,
  lastName: String,
  email: {type: String, unique: true},
  password: String
}));

var app = express();
app.set('view engine', 'jade');
app.locals.pretty = true;

mongoose.connect('mongodb://localhost/newauth');

//app.use functions all called before the route functions

//middleware
app.use(bodyParser.urlencoded({extended: true}));//makes the body of http request (Ex:forms) available via req.body

app.use(session({
  cookieName: 'session',
  secret: 'ahfaiuef8w95279729shkfshkf',
  duration: 30 * 60 * 1000, //30 minutes
  activeDuration: 5 * 60 * 1000 //lengthens 5 minutes more if active,
  httpOnly: true, //dont let browser access cookies ever
  secure: true, //only use cookies over https
  ephemeral: true //delete this cookie when browser closes
}));

//prevents form submission without submit (so even if logged it, and http call made via trick link, form wont submit)
app.use(csrf());

//always gets called
app.use(function (req, res, next) {
  if(req.session && req.session.user){
    User.findOne({email: req.session.user.email}, function(err, user){
      if(user){
        req.user = user;
        delete req.user.password;
        req.session.user = req.user;
        res.locals.user = req.user;
      }
      next();
    });
  }else{
    next();
  }
});

function requireLogin(req, res, next){
  if(!req.user){
    res.redirect('/login');
  } else {
    next();
  }
}



app.get('/', function(req, res){
  res.render('index.jade');
});

app.get('/login', function(req, res){
  //csrf token needed for pages that have forms
  res.render('login.jade', {csrfToken: req.csrfToken()});
});

app.post('/login', function(req, res){
  User.findOne({email: req.body.email}, function(err, user){
    if(!user){
      res.render('login.jade', {error: 'invalid email or password.'});
    }else{
      if(bcrypt.compareSync(req.body.password, user.password)){
        req.session.user = user; //set-cookie: session = {email, firstName..}
        res.redirect('/dashboard');
      }else{
        res.render('login.jade', {error: 'invalid email or password.'});
      }
    }
  })
});

app.get('/register', function(req, res){

  //csrf token needed for pages that have forms
  res.render('register.jade', {csrfToken: req.csrfToken()});
});

app.post('/register', function(req, res){
  var data = req.body;
  var hash = bcrypt.hashSync(data.password, bcrypt.genSaltSync(10));
  var user = new User({
    firstName: data.firstName,
    lastName: data.lastName,
    email: data.email,
    password: hash
  })
  user.save(function(err){
    if(err) {
      var error = 'something went wrong! Try again!';
      if(err.code = '11000'){
        error = 'Email already exists';
      }
      res.render('register.jade', {error:error});
    }else{
      res.redirect('/dashboard');
    }
  })

});

app.get('/dashboard', requireLogin, function(req, res){
    res.render('dashboard.jade');
});

app.get('/logout', function(req, res) {
  if (req.session) {
    req.session.reset();
  }
  res.redirect('/');
});


//TODO: forgot password route and page


app.listen(3000);