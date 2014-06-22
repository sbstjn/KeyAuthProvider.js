(function() {
  'use strict';

  var express = require('express');
  var http = require('http');
  var ursa = require('ursa');
  var fs = require('fs');

  /**
   * Temporary in-Memory storage for tokens
   */
  var TokenStorage = function() {
    this.data = {};
  };

  TokenStorage.prototype.validateRequest = function(site, token, callback) {
    callback(this.data[site] && this.data[site].request === token && this.data[site].auth === null);
  };

  TokenStorage.prototype.setAuth = function(site, auth, callback) {
    this.data[site].auth = auth;

    callback(auth);
  };

  TokenStorage.prototype.createToken = function(site, token, callback) {
    this.data[site] = {request: token, auth: null, created: new Date()};

    callback(token);
  };

  TokenStorage.prototype.checkSession = function(site, token, callback) {
    callback(this.data[site] && this.data[site].auth === token);
  };

  /**
   * KeyAuthConsumer Constructor
   */
  var KeyAuthProvider = function(data) {
    this.http = 'http';
    this.name = data.name;
    this.about = data.about;
    this.tokens = {};
    this.redirect = data.redirect;
    this.template = data.template;
    this.storage = new TokenStorage();

    // Load private RSA key
    fs.readFile(data['private'], function(err, data) {
      this.keyPrivate = data;
    }.bind(this));

    // Load avatar
    fs.readFile(data.avatar, function(err, data) {
      this.avatar = data;
    }.bind(this));
  };


  /**
   * Handle /about request with information about this consumer instance
   */
  KeyAuthProvider.prototype.handleAbout = function() {
    return function(req, res) {
      res.json({
        name: this.name,
        about: this.about
      });
    }.bind(this);
  };

  /**
   * Handle request for consumer avatar
   */
  KeyAuthProvider.prototype.handleAvatar = function() {
    return function(req, res) {
      res.write(this.avatar);
      res.end();
    }.bind(this);
  };

  /**
   * Handle request for consumer rsa public key
   */
  KeyAuthProvider.prototype.handleKey = function() {
    return function(req, res) {
      res.write(this.key);
      res.end();
    }.bind(this);
  };

  /**
   * Get information from KeyAuthConsumer
   */
  KeyAuthProvider.prototype.getConsumerInfo = function(name, callback) {
    var client = name.split(':');

    var options = {
      host: client.shift(),
      path: '/about',
      port: client.shift() || 80
    };

    var handle = function(response) {
      var str = '';

      //another chunk of data has been recieved, so append it to `str`
      response.on('data', function (chunk) {
        str += chunk;
      });

      //the whole response has been recieved, so we just print it out here
      response.on('end', function () {
        var data = {};
        try {
          data = JSON.parse(str);
          data.key = client + data.key;
          data.avatar = client + data.avatar;
        } catch (e) { }

        callback(data);
      });
    };

    http.request(options, handle).end();
  };

  /**
   * Create Auth Token for consumer
   */
  KeyAuthProvider.prototype.createAuth = function(site, token, callback) {
    this.storage.validateRequest(site, token, function(valid) {
      if (!valid) {
        callback(null);
      } else {
        this.storage.setAuth(site, Math.random().toString(36).slice(2), function(auth) {
          callback(auth);
        });
      }
    }.bind(this));
  };

  /**
   * Create first Token for handshake with consumer
   */
  KeyAuthProvider.prototype.createToken = function(site, callback) {
    this.storage.createToken(site, Math.random().toString(36).slice(2), function(token) {
      callback(token);
    });
  };

  /**
   * Check password for private RSA key
   */
  KeyAuthProvider.prototype.checkPassword = function(password, callback) {
    var valid = false;
    try {
      ursa.createPrivateKey(this.keyPrivate, password);

      valid = true;
    } catch (e) { }

    callback(valid);
  };

  /**
   * Show login form
   */
  KeyAuthProvider.prototype.showLogin = function(req, res) {
    this.getConsumerInfo(req.param('client_id'), function(data) {
      req.session.client = data;

      res.render(this.template, {client: req.session.client});
    }.bind(this));
  };

  /**
   * Process login data
   */
  KeyAuthProvider.prototype.processData = function(req, res) {
    this.getConsumerInfo(req.param('client_id'), function(data) {
      req.session.client = data;

      this.checkPassword(req.body.password || '', function(valid) {
        req.session.keyauth = {valid: valid};

        if (valid) {
          this.createToken(req.session.client.name, function(token) {
            res.redirect('http://' + req.session.client.name + '/login/callback?token=' + token + '&provider=' + this.name);
          }.bind(this));
        } else {
          res.render(this.template, {client: req.session.client, keyauth: {failed: !valid, valid: valid}});
        }
      }.bind(this));
    }.bind(this));
  };

  /**
   * Wrapper for auth request handling
   **/
  KeyAuthProvider.prototype.handleAuth = function() {
    var router = express.Router();

    // Draw login form
    router.all('/', function(req, res, next) {
      var method = req.method.toUpperCase();

      switch(method) {
      case 'GET':
        this.showLogin(req, res, next);
        break;
      case 'POST':
        this.processData(req, res, next);
        break;
      }
    }.bind(this));

    // Handle token validation
    router.post('/validate', function(req, res) {
      this.createAuth(req.param('client_id'), req.param('token'), function(token) {
        res.json({
          valid: !!token,
          token: token
        });
      });
    }.bind(this));

    // Get basic user information with token
    router.post('/session', function(req, res) {
      this.storage.checkSession(req.param('client_id'), req.param('token'), function(valid) {
        res.json(valid ? {name: this.name} : {});
      }.bind(this));
    }.bind(this));

    return router;
  };

  /**
   * Bind express routes
   */
  KeyAuthProvider.prototype.expressBinding = function() {
    var router = express.Router();

    router.use('/auth',    this.handleAuth());

    // Basic profile JSON
    router.get('/about',   this.handleAbout());

    // Avatar image
    router.get('/avatar',  this.handleAvatar());

    // Public RSA key
    router.get('/key',     this.handleKey());

    return router;
  };

  module.exports = KeyAuthProvider;
})();
