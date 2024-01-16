const mongoose = require('mongoose')

const CommentSchema = new mongoose.Schema(
 {
    userId:{
        type: String,
        required: true
    },
    postId:{
        type: String,
        required: true
    },
    desc: {
        type: String,
        required: true
    },
    reply: [
        {
            userreplyId: {
                type: String,
                required: true
            },
            descreply: {
                type: String,
                require: true
            }
        }
        
    ]
 },
 {timestamps: true})

 module.exports = mongoose.model('Comment',CommentSchema)