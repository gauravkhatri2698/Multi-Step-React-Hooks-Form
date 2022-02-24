const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();
const db = require("../db");

router.post("/register", (req, res) => {
  const {
    user_email,
    user_password,
    first_name,
    last_name,
    country,
    state,
    city,
  } = req.body;

  if (user_email && user_password) {
    try {
      db.query(
        "SELECT user_email FROM User WHERE user_email=?",
        [user_email],
        async function (error, results) {
          if (error) {
            return res
              .status(500)
              .send(
                "Something went wrong while registering the user. Please contact to the administrator!"
              );
          } else if (results.length > 0) {
            return res
              .status(400)
              .send("User with the provided email already exixts.");
          } else {
            let hashedpassword = await bcrypt.hash(user_password, 8);

            db.query(
              "INSERT INTO User SET ?",
              {
                first_name: first_name,
                last_name: last_name,
                user_email: user_email,
                user_password: hashedpassword,
                country: country,
                state: state,
                city: city,
              },
              function (error, results) {
                if (error) {
                  return res
                    .status(500)
                    .send(
                      "Something went wrong while registering the user. Please check the details that you have entered and correct them if missing or invalid!"
                    );
                } else {
                  return res.status(201).send("User has been registered!");
                }
              }
            );
          }
        }
      );
    } catch (error) {
      return res.status(500).send("Something went wrong. Please contact to the administrator!");
    }
  } else {
    return res
      .status(500)
      .send(
        "Something went wrong while registering the user. Please check the details that you have entered and correct them if missing or invalid!"
      );
  }
});

router.post("/login", async (req, res) => {
  try {
    db.query(
      "SELECT * FROM User WHERE user_email=?",
      [req.body.user_email],
      async function (error, user) {
        if (error)
          return res
            .status(500)
            .send(
              "Something went wrong while login the user. Please contact to the administrator!"
            );
        else {
          if (user.length === 0) {
            return res
              .status(400)
              .send("User with provided email does not exist.");
          }

          const isMatch = await bcrypt.compare(
            req.body.user_password,
            user[0].user_password
          );

          if (!isMatch) {
            return res
              .status(400)
              .send(
                "Invalid credentials. Please login with the correct username or passowrd"
              );
          }
          const { user_password, ...rest } = user[0];

          return res.status(200).send(rest);
        }
      }
    );
  } catch (error) {
    return res.status(500).send("Something went wrong. Please contact to the administrator!");
  }
});

module.exports = router;
