import crypto from "crypto";

/* const text = "Hello World!";

const hashedText = crypto.createHash("sha256").update(text).digest("base64");
const hmacText = crypto
  .createHmac("sha256", "secret")
  .update(text)
  .digest("base64");
console.log(hmacText);
console.log(hashedText); */

const key = crypto.randomBytes(32).toString("hex");
const hashKEY = crypto.randomBytes(32).toString("hex");
console.log(hashKEY, "hash key");
