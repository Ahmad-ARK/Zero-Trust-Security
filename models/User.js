const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  lastLoginIP: String,
  lastUserAgent: String,
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String }, // For storing the TOTP secret
});


module.exports = mongoose.model("User", userSchema);
