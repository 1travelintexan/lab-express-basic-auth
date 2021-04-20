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
      console.log("there was an error");
    });

  // Validate an email: it should have an @ and . symbol in it
  //   const re = /^[^@ ]+@[^@ ]+\.[^@ ]+$/;
  //   if (!re.test(String(username).toLowerCase())) {
  //     res.render("auth/signup.hbs", { msg: "Please enter a valid username" });
  //     // tell node to come out of the callback code
  //     return;
  //   }
});

module.exports = router;
