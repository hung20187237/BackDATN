const mongoose = require("mongoose");

const PostSchema = new mongoose.Schema(
  {
    userId: {
      type: String,
      required: true,
    },
    desc: {
      type: String,
      max: 500,
    },
    img: {
      type: Array,
      default: [],
    },
    likes: {
      type: Array,
      default: [],
    },
    saveposts: {
      type: Array,
      default: [],
    },
    title: {
      type: String,
      max: 100,
    },
    tagkv: {
      type: String,
    },
    tagtc: {
      type: String,
    },
    tagdm: {
      type: String,
    },
    rating: {
      type: Object,
      properties: {
          place: {type: Number},
          space: {type: Number},
          food: {type: Number},
          serve: {type: Number},
          price: {type: Number},
      }
    },
    place: {
      type: String,
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Post", PostSchema);