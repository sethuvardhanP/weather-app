const express = require("express");
const app = express();
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const bodyParser = require('body-parser');
const path = require('path');


app.use(express.static(path.join(__dirname, "views")));

const serviceAccount = require('./key.json');

initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));


const bcrypt = require('bcrypt');
const saltRounds = 10;


app.get("/", function (req, res) {
    res.redirect("/signup");
});


app.get("/signup", function (req, res) {
    res.render("signup");
});


app.get("/login", function (req, res) {
    res.render("login");
});



app.get("/dashboard", function (req, res) {
    res.render("dash");
});


app.post("/signupSubmit", function (req, res) {
    const { email, password, fullname } = req.body;


    bcrypt.hash(password, saltRounds, function (err, hash) {
        if (err) {
            console.error("Error hashing password:", err);
            return res.status(500).send("Error: Unable to sign up. Please try again later.");
        }

        db.collection("users")
            .add({
                email: email,
                password: hash,
                fullname: fullname
            })
            .then(() => {
                res.render("signupsucess");
            })
            .catch((error) => {
                console.error("Error adding document: ", error);
                res.status(500).send("Error: Unable to sign up. Please try again later.");
            });
    });
});

app.post("/loginSubmit", function (req, res) {
    const { email, password } = req.body;
    db.collection("users")
        .where("email", "==", email)
        .get()
        .then((docs) => {
            if (docs.empty) {
                return res.send("User not found.");
            }
            const user = docs.docs[0].data();
            bcrypt.compare(password, user.password, function (err, result) {
                if (err) {
                    console.error("Error comparing passwords:", err);
                    return res.status(500).send("Error: Unable to login. Please try again later.");
                }
                if (result) {
                    res.redirect("/dashboard");
                } else {
                    res.send("Incorrect password.");
                }
            });
        })
        .catch((error) => {
            console.error("Error getting documents: ", error);
            res.status(500).send("Error: Unable to login. Please try again later.");
        });
});




app.listen(3000, () => {
    console.log("Listening at http://localhost:3000");
});