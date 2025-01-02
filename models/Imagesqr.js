// backend/models/BusinessData.js
const mongoose = require('mongoose');

const ImagesDataSchema = new mongoose.Schema({
    Images_title:{
        type: String,
        // required: true,
    },
    Images_description:{
        type: String,
        // required: true,
    },

  Images_btn_text: {
    type: String,
    // required: true,
  },
  Images_btn_url: {
    type: String,
    // required: true,
  },
  Images: {
    type: [String],  // Array of image URLs
  },
  Social_welcome_screen: {
    type: String,  // This field contains the welcome screen text and image URL
    // required: true,
  },
  Social_welcome_screen_time: {
    type: Number,  // Time in seconds
    // required: true,
  },
  social_display_theme:{
    type: String,
    defualt: 'default',
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'UserLogin',
    // required: true,
  },
}, { timestamps: true });

module.exports = mongoose.model('Images', ImagesDataSchema);