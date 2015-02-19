var express = require("express");
var https = require('https');
var http = require('http');
var  fs  =require('fs');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var sessions = require('client-sessions');
var bcrypt = require('bcryptjs');
var csrf = require('csurf');
var app = express();

var  Schema =  mongoose.Schema;
var ObjectId = Schema.ObjectId;

var User = mongoose.model('User', new Schema({
	id: ObjectId,
	firstName : String,
	lastName : String,
	email: {type : String, unique: true},
	password: String,
}));


mongoose.connect('mongodb://localhost/cms');

app.set('view engine', 'jade');
app.locals.pretty = true;

/*middlerware*/
app.use(bodyParser.urlencoded({extended: true}));
app.use(sessions({
	cookieName: 'session',
	secret : '3120j0wej0134ja0j9013asj0575a0934'+Math.floor((Math.random() * 10000) + 1),
	duration : 7 * 60 * 1000,
	activeDuration: 5 * 60 * 1000,
	httpOnly: true, //navegador nunca acesse meus cookies
	secure: true, //cookies samente https
	ephemeral: true, //deletar cookie quando nevagador fechar

}));
app.use(csrf());

app.use(function(req , res, next) {
	if(req.session && req.session.user){
		User.findOne({email : req.session.user.email},function(err,user) {
			if(user){
				req.user = user;
				delete req.user.password;
				req.session.user = req.user;
				res.locals.user =  req.user;
			}
			next();
		});
	}else{
		next();
	}
});

function requireLogin(req , res, next) {
	if(!req.user){
		res.redirect('/login');
	}else{
		next();
	}
}

app.get('/register',function(req, res) {
	res.render('register.jade',{ csrfToken :  req.csrfToken() });
});

app.post('/register',function(req, res) {
	var hash = bcrypt.hashSync(req.body.password , bcrypt.genSaltSync(10));
	var user = new User({
		firstName : req.body.firstName,
		lastName : req.body.lastName,	
		email	 : req.body.email,
		password : hash,
	});

	user.save(function(err) {
		if(err){
			var error = 'Algo esta errado';
			if(err.code === 11000){
				error = "Esse email ja esta em uso tente outro";
			}
			res.render('register.jade',{error :error});
		}else{
			res.redirect('/dashboard');
		}
	});
});

app.get('/login',function(req, res) {
	res.render('login.jade',{ csrfToken :  req.csrfToken() });
});

app.post('/login',function(req, res) {
	User.findOne({email: req.body.email},function(err, user) {
		if(!user){
			res.render('login.jade',{error : 'Email ou senha Invalidos'});
		}else{
			if(bcrypt.compareSync(req.body.password , user.password)){
				req.session.user = user; // recebendo os dados para session
				res.redirect('/dashboard');
			}else{
				res.render('login.jade',{error : 'Email ou senha Invalidos'});
			}
		}

	})
});
app.get('/logout',function(req, res) {
	req.session.reset();
	res.redirect('/');
});

app.get('/dashboard', requireLogin, function(req, res) {
	res.render('dashboard.jade');
});

app.get('/',function(req, res) {
	res.render('index.jade');
});

var options = {
 	key: fs.readFileSync('agent2-key.pem'),
  cert: fs.readFileSync('agent2-cert.pem')
};

http.createServer(app).listen(8080);
https.createServer(options, app).listen(3000);

