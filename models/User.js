const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            require: true,
            min: 3,
            max: 20,
            unique: true,
        },
        email: {
            type: String,
            required: true,
            max: 50,
            unique: true,
        },
        role: {
            type: String,
            default: "user"
        },
        status: {
            type: String,
            default: "1"
        },
        password: {
            type: String,
            required: true,
            min: 6,
        },
        avatar: {
            type: String,
            default: "",
        },
        background: {
            type: String,
            default: "",
        },
        followers: {
            type: Array,
            default: [],
        },
        followings: {
            type: Array,
            default: [],
        },
        savedposts: {
            type: Array,
            default: [],
        },
        friends: {
            type: Array,
            default: []
        },
        city: {
            type: String,
            max: 50,
        },
        from: {
            type: String,
            max: 50,
        },
    },
    {timestamps: true}
);

module.exports = mongoose.model("User", UserSchema);