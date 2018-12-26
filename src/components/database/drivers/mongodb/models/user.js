// Load required packages
import mongoose from 'mongoose';
import moment from 'moment';
import bcrypt from 'bcrypt';
import uuid from 'uuid/v4';
import forge from 'node-forge';

import {encrypt, decrypt} from 'utils/security';

// Define our product schema
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true,
    },
    password: {
        type: String,
        required: true,
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

    if (this.session_token === null || !this._id) {
        // set the date for when it was created
        this.session_token = uuid();
    }

    if (!this._id || (this.isModified('password') && typeof this.password !== 'undefined')) {
        // hash the password with SHA256, as bcrypt is limited to 72 characters
        const passwordHMAC = forge.hmac.create();
        passwordHMAC.start('sha256', process.env.SECURITY_HMAC_SECRET);
        passwordHMAC.update(this.password, 'utf8');
        const passwordHash = passwordHMAC.digest().toHex();

        // then hash the sha256 with bcrypt
        const finalPasswordHash = await bcrypt.hash(
            passwordHash,
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

        const passwordHMAC = forge.hmac.create();
        passwordHMAC.start('sha256', process.env.SECURITY_HMAC_SECRET);
        passwordHMAC.update(submittedPassword, 'utf8');
        const passwordHash = passwordHMAC.digest().toHex();

        return bcrypt.compare(passwordHash, decryptedPasswordHash);
    } catch (err) {
        return false;
    }
};
/* eslint-enable no-invalid-this */

// Export the Mongoose model
module.exports = mongoose.model('User', UserSchema);
