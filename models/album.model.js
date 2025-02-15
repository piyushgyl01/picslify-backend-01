const mongoose = require("mongoose");

const albumSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    description: {
      type: String,
    },
    owner: {
      type: String,
      required: true,
    },
    sharedUsers: [{ type: String }],
  },
  { timestamps: true }
);

const Album = mongoose.model("picslifyAlbum", albumSchema);

module.exports = Album;