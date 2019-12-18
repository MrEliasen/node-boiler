// Load required packages
import mongoose from 'mongoose';

// Define our product schema
const AccountSchema = new mongoose.Schema({
    // user details
    username: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    session_token: {
        type: String,
        required: true,
    },
    created_date: {
        type: Date,
        required: true,
    },
});

// Export the Mongoose model
module.exports = mongoose.model('Account', AccountSchema);
