const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true }, // Ensures username uniqueness
  email: { type: String, required: true, unique: true }, // Ensures email uniqueness
  password: { type: String, required: true },
  lastLoginIP: String,
  lastUserAgent: String,
});

module.exports = mongoose.model("User", userSchema);
