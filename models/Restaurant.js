const mongoose = require("mongoose");

const RestaurantSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    places: {
      type: String,
      require: true,
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Restaurant", RestaurantSchema);
