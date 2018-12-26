// Load required packages
import mongoose from 'mongoose';
import moment from 'moment';

// Define our product schema
const ProviderSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
    },
    profileId: {
        type: String,
        required: true,
    },
    provider: {
        type: String,
        required: true,
    },
    created: String,
    lastUpdated: String,
});

// Execute before each user.save() call
/* eslint-disable no-invalid-this */
ProviderSchema.pre('save', async function(callback) {
    // set the date for when it was updated
    this.lastUpdated = moment().utc().format();

    // set the date for when it was created
    if (!this.created && !this._id) {
        this.created = moment().utc().format();
    }

    callback();
});

// Export the Mongoose model
module.exports = mongoose.model('Provider', ProviderSchema);
