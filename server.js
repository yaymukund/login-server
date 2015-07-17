var bcrypt = require('bcrypt'),
    express = require('express'),
    config = require('./.config'),
    bodyParser = require('body-parser'),
    session = require('express-session'),
    FileStore = require('session-file-store')(session);

var app = express();

app.use(session({
  cookie: { maxAge: 1000 * 60 * 24 * 7 },
  store: new FileStore(),
  secret: config.session_secret
}));

app.use(bodyParser.urlencoded());

var login = function(password, done) {
  bcrypt.compare(password, config.password_digest, function(err, res) {
    return done(!!res);
  });
};

app.get('/session', function(req, res) {
  res.sendStatus(!!req.session.isLoggedIn ? 200 : 403);
});

app.post('/authenticate', function(req, res) {
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
