const router = require("express").Router();
const bcrypt = require("bcryptjs");
const UserModel = require("../models/User.model");

//get route to show the sign in form
router.get("/signin", (req, res) => {
  res.render("auth/signin.hbs");
});

//get route to show the sign up form
router.get("/signup", (req, res) => {
  res.render("auth/signup.hbs");
});

//post route for more info
router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;

  //inputs
  if (!username || !password) {
    res.render("auth/signup.hbs", { msg: "Please enter all info" });
    return;
  }

  //valid password
  // use a regEx
  const passRe = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
  if (!passRe.test(password)) {
    res.render("auth/signup.hbs", {
      msg:
        "Password must be 8 characters, must have a number, and an uppercase Letter",
    });
    // tell node to come out of the callback code
    return;
  }

  const salt = bcrypt.genSaltSync(12);
  const hash = bcrypt.hashSync(password, salt);

  UserModel.create({ username, password: hash })
    .then(() => {
      res.redirect("/");
    })
    .catch((err) => {
      next("err");
    });
});

//iteration 2
//loggin in page
router.post("/signin", (req, res, next) => {
  const { username, password } = req.body;

  UserModel.findOne({ username })
    .then((response) => {
      if (!response) {
        res.render("auth/signin.hbs", { msg: "Username is not a match" });
      } else {
        bcrypt.compare(password, response.password).then((isMatching) => {
          if (isMatching) {
            req.session.userInfo = response;
            req.app.locals.isUserLoggedIn = true;
            res.redirect("/profile");
          } else {
            res.render("auth/signin", { msg: "Password is incorrect" });
          }
        });
      }
    })
    .catch((err) => {
      next(err);
    });
});

//protected routes
router.get("/profile", authorize, (req, res, next) => {
  const { username } = req.session.userInfo;
  res.render("profile.hbs", { username });
});

router.get("/logout", (req, res, next) => {
  // set the global variable 'isUserLoggedIn' so that we can use it in layout.hbs
  req.app.locals.isUserLoggedIn = false;

  // deletes a specific session from mongoDB
  req.session.destroy();
  res.redirect("/");
});

module.exports = router;
