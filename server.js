var bcrypt = require('bcrypt'),
    express = require('express'),
    config = require('./.config'),
    bodyParser = require('body-parser'),
    session = require('express-session'),
    FileStore = require('session-file-store')(session),
    TTL_SECONDS = 60 * 60 * 24 * 7;

var app = express();

app.use(session({
  cookie: { maxAge: 1000 * TTL_SECONDS },
  resave: false,
  saveUninitialized: false,
  store: new FileStore({ ttl: TTL_SECONDS }),
  secret: config.session_secret
}));

var login = function(password, done) {
  bcrypt.compare(password, config.password_digest, function(err, res) {
    return done(!!res);
  });
};

app.use(function(req, res, next) {
  console.log('%s %s %s', req.method, req.url, req.path);
  next();
});

app.get('/session', function(req, res) {
  res.sendStatus(!!req.session.isLoggedIn ? 200 : 403);
});

app.post('/authenticate', bodyParser.urlencoded({ extended: false }), function(req, res) {
  login(req.body.password, function(success) {
    if (!success) {
      res.sendStatus(401);
    } else {
      req.session.isLoggedIn = true;
      res.redirect('/');
    }
  });
});

app.get('/login', function(req, res) {
  if (req.session.isLoggedIn) {
    res.redirect('/');
    return;
  }

  res.sendFile('login.html', { root: __dirname });
});

app.listen(3001);
