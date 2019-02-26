// Load required packages
import mongoose from 'mongoose';
import moment from 'moment';
import argon2 from 'argon2';
import uuid from 'uuid/v4';
import forge from 'node-forge';

import {encrypt, decrypt} from 'utils/security';

// Define our product schema
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
    },
    password: {
        type: String,
    },
    sessionToken: {
        type: String,
    },
    created: String,
    lastUpdated: String,
});

// Execute before each user.save() call
/* eslint-disable no-invalid-this */
UserSchema.pre('save', async function(callback) {
    // set the date for when it was updated
    this.lastUpdated = moment().utc().format();

    // set the date for when it was created
    if (!this.created && !this._id) {
        this.created = moment().utc().format();
    }

    if (this.sessionToken === null || !this._id) {
        // set the date for when it was created
        this.sessionToken = uuid();
    }

    if (!this._id || (this.isModified('password') && typeof this.password !== 'undefined')) {
        // then hash the password with argon2
        const finalPasswordHash = await argon2.hash(
            this.password,
            parseInt(process.env.SECURITY_PASSWORD_ROUNDS, 10)
        );

        // and encrypt the hash
        const encryptedPassword = await encrypt(finalPasswordHash);
        this.password = forge.util.encode64(JSON.stringify(encryptedPassword));
    }

    callback();
});

UserSchema.methods.verifyPassword = async function(submittedPassword) {
    try {
        if (!this.password) {
            return false;
        }

        const passwordCipherData = forge.util.decode64(JSON.parse(this.password));

        if (!passwordCipherData.iv || !passwordCipherData.cipherText) {
            return false;
        }

        const decryptedPasswordHash = await decrypt(
            passwordCipherData.cipherText,
            passwordCipherData.iv
        );

        return argon2.verify(decryptedPasswordHash, submittedPassword);
    } catch (err) {
        return false;
    }
};
/* eslint-enable no-invalid-this */

// Export the Mongoose model
module.exports = mongoose.model('User', UserSchema);
