var bcrypt = require("bcrypt");
var ObjectID = require("mongodb").ObjectID;


/*
    Dependencies:
        bcrypt              password encryption purposes
        mongodb             the database driver

    Expected Server Variables:
        req.dbo             relevant database object for finding and storing user information
        req.session         relevant session for storing relevant session user data
        req.client_data     post/get data from the client

    Expected Client Variables:
        email:              user's email for login
        password:           user's password for login
        action:             form action should be "login" to access this middleware
        func:               the function of the login middleware, ie: "login", or "create_user"
    
    Expected Database Fields:
        email:              user's email, a unique field,
        password:           user's password, encyrpted by this function
        verified:           a string field indicating whether this user has verified his account ... "true" for verified, anything else for not verified (including the code to verify)

*/
function handle_login(req,res, next) {
    var data = req.client_data;
    if (data.action != "login") { next(); return; }
    console.log("Within handle_login.js....");
    var dbo = req.dbo;
    var session = req.session;

    //handle login post information here. Should have req.client_data object for all relevant data
    if (data.func == "create_user") {
        var n = data.email;
        var p = data.password;
        //encrypt password here
        bcrypt.genSalt(10,(_err,salt) => {
            bcrypt.hash(p,salt,(__err,hash) => {
                if (__err) { return; }
                //insert user here
                var verification_code = new ObjectID();
                var insert_obj = {
                    email: n,
                    password: hash,
                    permissions: [],
                    verified: verification_code,
                }
                dbo.collection("Users").insertOne(insert_obj,(error, response) => {
                    if (error) {
                        //typical failure occurs here if email has already been used to make an account
                        res.send("-1");
                    } else {
                        //user creation success
                        res.send("1");
                    }
                });

            });
        });

    } else if (data.func == "login") {
        var n = data.email;
        var p = data.password;
        dbo.collection("Users").find({email: n}).limit(1).next((_err, _res) => {
            if (_err) { console.log(_err.message); res.send("-1"); return; }
            bcrypt.compare(p,_res.password,(__err, __res) => {
                if (__res) {
                    //login success
                    session.user = _res;
                    session.logged_in = true;
                    
                    res.send(req.session);
                } else {
                    //on a failed login destroy the session
                    session.destroy();
                }
                //always save the session to ensure it updates with any new data
                session.save();
            });
        });
    } else if (data.func == "logout") {
        req.session.destroy();
        res.send("1");
    } else if (data.func == "verify") {
        var code = data.code;
        //search the database for the particular ObjectID code generated on account creation
        //if the code is found assume the account and email are verified
        dbo.collection("Users").find({verified: new ObjectID(code)}).limit(1).next((error, result) => {
            if (error) { console.log(error.message); return; }
            console.log("Result: ")
            console.log(result);
            if (result) {
                req.session.user.verified = true;
                dbo.collection("Users").update({verified: new ObjectID(code)},{$set: { verified: 1 }});
            } else {
                req.session.user.verified = false;
            }
            next();
        });
    } else {
        next();
    }
}

exports.main = handle_login;