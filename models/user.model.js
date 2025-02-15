const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: { 
      type: String, 
      required: true, 
      unique: true 
    },
    name: { 
      type: String, 
      required: true 
    },
    password: { 
      type: String, 
      required: true 
    },
    profilePicture: { 
      type: String,
      default: null
    }
  },
  { timestamps: true }
);

const User = mongoose.model("picslifyUser", userSchema);

module.exports = User;