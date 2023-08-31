//jshint esversion:6
require("dotenv").config();
 const express=require("express");
 const bodyParser=require("body-parser");
 const ejs=require("ejs");
 const app=express();
 const mongoose=require("mongoose");
 const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require("mongoose-findorcreate");

//  const encrypt=require("mongoose-encryption");
// const md5=require("md5");       //hash function
// const bcrypt=require("bcrypt");  //bcrypt hashing
// const saltRounds=10;

//  console.log(process.env.SECRET);

 app.set("view engine","ejs");
 app.use(bodyParser.urlencoded({extended:true}));
 app.use(express.static("public"));
app.use(session({
    secret:"my lil secret",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

 mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema= new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:[String]
});

// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=mongoose.model("User",userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
   
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

 app.get("/",function(req,res){
    res.render("home");
 });

 app.get("/auth/google",
    passport.authenticate("google",{scope:["profile"]}));

app.get("/auth/google/secrets",
    passport.authenticate("google",{failureRedirect:"/login"}),
    function(req,res){
        res.redirect("/secrets");
    }
);

 app.get("/login",function(req,res){
    res.render("login");
 });

 app.get("/register",function(req,res){
    res.render("register");
 });

 ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  app.post("/register",function(req,res){
//     myPlaintextPassword=req.body.password;
//     bcrypt.hash(myPlaintextPassword,saltRounds,function(err,hash){
//         const newUser=new User({
//             email:req.body.username,
//             // password:md5(req.body.password)
//             password:hash
//         });
//         newUser.save().then(function(){
//             res.render("secrets");
//         }).catch(err =>{
//             console.log("error");
//         })
//     })
//  });

//  app.post("/login",function(req,res){
//     const username=req.body.username;
//     // const password=md5(req.body.password);
//     const password=req.body.password;
//     User.findOne({email:username}).then(function(foundUser){
//         if(foundUser){
//             bcrypt.compare(password,foundUser.password,function(err,result){
//                 if(result==true){
//                     res.render("secrets");
//                 }
//             })
//         }
//     }).catch(err=>{
//         console.log("error here");
//     })
//  });
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get("/secrets",function(req,res){
    User.find({"secret":{$ne:null}}).then(function(foundUser){
        if(foundUser){
            res.render("secrets",{usersWithSecrets:foundUser});
        }
    }).catch(err=>{
        console.log("error");
    })
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret;

    User.findById(req.user.id).then(function(foundUser){
        if(foundUser){
            foundUser.secret=submittedSecret;
            foundUser.save().then(function(){
                res.redirect("/secrets");
            })
        }
    }).catch(err=>{
        console.log("error");
    })
});

app.post("/register",function(req,res){
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log("error");
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/login",function(req,res){
    const user=new User({
        username:req.body.username,
        password:req.body.password
    });
    
    req.login(user,function(err){
        if(err){
            console.log("error");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
        }
    })
});

app.get("/logout", function(req, res){
    req.logout(function(err) {
      if (err) { 
        console.log("error"); 
    }else{
        res.redirect('/');
    }
    });
  });

 app.listen(3000,function(req,res){
    console.log("Server is running at port 3000");
 });