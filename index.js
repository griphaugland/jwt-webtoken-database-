import express from "express";
import mysql from "mysql";
import "dotenv/config";
import crypto from "crypto";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

try {
  connection.connect();
  console.log("connection success");
} catch (e) {
  console.log("connection failed");
}

app.get("/", (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  try {
    const verifiedToken = jwt.verify(token, process.env.TOKEN_HASH_KEY);
    if (verifiedToken) {
      connection.query(
        "SELECT `id`, `username` FROM `users`",
        (err, rows, fields) => {
          if (err) {
            console.log("Something went wrong");
          } else {
            res.json(rows);
          }
        }
      );
    } else {
      res.status(404).json({
        message: "invalid token",
      });
    }
  } catch (e) {
    res.status(404).json({
      message: "invalid token or an error occured",
    });
  }
});

app.post("/register", (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = crypto
    .createHmac("sha256", process.env.HASH_KEY)
    .update(password)
    .digest("base64");

  connection.query(
    "INSERT INTO `users`( `username`, `email`, `password`) VALUES (?, ?, ?)",
    [username, email, hashedPassword],
    (err, rows, fields) => {
      if (err) {
        res.json({
          message: "Something went wrong",
        });
      } else {
        res.json({
          message: "Accepted credentials, Registered.",
        });
      }
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  /*  
  Annen måte å escape string for å unngå php injection attacks
  
  const queryValue = connection.escape(username); */
  const hashedInputPassword = crypto
    .createHmac("sha256", process.env.HASH_KEY)
    .update(password)
    .digest("base64");

  connection.query(
    "SELECT * FROM `users` WHERE username = ?",
    [username],
    (err, rows, fields) => {
      if (err) {
        console.log("Something went wrong");
      } else {
        if (rows[0].password === hashedInputPassword) {
          const token = jwt.sign(
            { user: username },
            process.env.TOKEN_HASH_KEY
          );
          res.json({
            message: `Correct credentials, logged in as ${username}.`,
            accessToken: token,
          });
        } else {
          res.status(401).json({
            message: " Invalid username or password",
          });
        }
      }
    }
  );
});

app.listen(3000, () => {
  console.log("Server started on port 3000");
});
