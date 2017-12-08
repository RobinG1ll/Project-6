#!/usr/bin/node
/** Dependencies/required modules */
var express = require('express');
var port = process.env.PORT || 8080;
var http = require('http');

var bp = require('body-parser');
var fs = require('fs');
var jsonfile = require('jsonfile');

var speakeasy = require('speakeasy');
var QRCode = require('qrcode');
const bcrypt = require("bcrypt-nodejs");
/*
/** Speakeasy components **/
var secret;

/** Stores users as JSON */
var userfile = "users.txt";

/** Initialize express.js and its templates */
var app = express();
app.use(bp.urlencoded({ extended: true }));
app.set('views', './views');
app.set('view engine', 'pug');

/** Initialize the Web Server */
http.createServer(app).listen(port, function () {
	console.log("Web Server is listening on port " + port);
});

/** Default Page
		Renders template from view/login.pug
 */
app.get('/', function(req, res) {
	res.render('login');
});

/** Checks credentials when POST to /login-check
		Parses JSON file for usernames
		Compares post data with stored data
 */
app.post('/login-check', function(req, res) {

/** Load User "database" */
	jsonfile.readFile(userfile, function(er, data) {

/** Returns filtered object.
		Should return exactly one object when username and password match an entry.
 */
		var found = data.filter(function(item) {
            var user = false;
			if(item.twofactor == "enabled"){
                var verified = speakeasy.totp.verify({ secret: item.token,
                    encoding: 'base32',
                    token: req.body.token });

                if (item.name == req.body.name) {
                	if(verified){
                        user = bcrypt.compareSync(req.body.password, item.password);
					} else {
                		return user;
					}
                }
			}
			if(item.twofactor == "disabled"){
				if (item.name == req.body.name) {
					user = bcrypt.compareSync(req.body.password, item.password);
				}
            }
			return user;
		});
/** Checks if the filtered object is exactly one.
		Displays success if it is (because username and password matched)
		Displays failure if any value other than zero
 */
		if (Object.keys(found).length == 1) {
			res.send("Login successful!")
		}
		else {
			res.send("Login failed because of wrong password or non-existing account or wrong token.")
		}
		// check for non-existing user

	});
});

/** New user page. Renders template from views/newuser.pug */
app.get('/add-users', function(req, res) {
	res.render('newuser');
});

/** Current users page.
 		Reads userfile "database".
		Renders template from views/users.pug by passing the users object
 */
app.get('/users', function(req, res) {
	jsonfile.readFile(userfile, function(err, obj){
		if (err) throw err;
		console.log(obj);
		res.render('users', { users: obj });
	});
});

/** Add users page.
 		Reads userfile "database".
		Appends JSON object with POST data to the old userfile object.
		Writes new object to the userfile.
 */

app.post('/adduser', function(req, res) {
// storing users in file
		//Two factor authenticator check
		var twofactorauth = "disabled";
		if(req.body.twofactor == "enabled"){
			twofactorauth = "enabled"
			var userSE = secret;
			var base32secret = userSE.base32;
            var verified = speakeasy.totp.verify({ secret: base32secret,
                encoding: 'base32',
                token: req.body.token });
            console.log(verified);

            if(verified) {
                console.log(req.body.token);
                bcrypt.hash(req.body.password, null, null, function(err, hash){
                    var userdata = { name: req.body.name, password: hash, twofactor: twofactorauth, token: base32secret};
                    console.log(hash);
                    jsonfile.readFile(userfile, function(er, data) {
                        data.push(userdata);
                        jsonfile.writeFile(userfile, data, (err) => {
                            res.send('successfully registered new user...<br>'
                            + '<a href="/users">Back to User List</a>');
                    });
                    })
                });
			} else {
                res.send('TOKEN INCORRECT!!!<br>'
                    + '<a href="/add-users">Back to create users</a>');
			}
		} else {
            bcrypt.hash(req.body.password, null, null, function(err, hash){
                var userdata = { name: req.body.name, password: hash, twofactor: twofactorauth};
                console.log(hash);
                jsonfile.readFile(userfile, function(er, data) {
                    data.push(userdata);
                    jsonfile.writeFile(userfile, data, (err) => {
                        res.send('successfully registered new user...<br>'
                        + '<a href="/users">Back to User List</a>');
                });
                })
            });
		}

});

app.post('/generate', function(req, res) {

	secret = speakeasy.generateSecret();
    QRCode.toDataURL(secret.otpauth_url, function(err, data_url) {
        res.send({
            status: "Success",
            url: data_url,
			secret: secret
        })
    })
})