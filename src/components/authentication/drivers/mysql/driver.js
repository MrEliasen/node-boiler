import validator from 'validator';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import uuid from 'uuid/v4';
import forge from 'node-forge';
import Authentication from 'components/authentication/authentication';

// helper/security
import {havePasswordBeenPwned, decrypt, encrypt} from 'utils/security';

/**
 * Authentication manager
 */
class AuthMySQL extends Authentication {
    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        super(server);
        this.driverName = 'MySQL';
    }

    /**
     * Will check barer token header and assign the user to req.user
     * @param  {Request}  req   Express Request object
     * @param  {Response} res   Express Response object
     * @param  {Function} next  Express next/callback
     */
    middleWareIsLoggedIn = async (req, res, next) => {
        try {
            const Authorization = '' + req.get('Authorization');
            const decoded = jwt.verify(Authorization, process.env.SECRETS_SIGNING_KEY);

            // check if the device name and ID matches
            if (decoded.ip !== req.ipInfo ? req.ipInfo.ipAddress : '' || decoded.agent !== req.useragent.source) {
                return null;
            }

            const account = await this.server.database.driver.query({
                sql: `SELECT
                            id
                        FROM
                            account
                        WHERE
                            id = ?
                        AND
                            sessionToken = ?
                        LIMIT
                            1`,
                values: [
                    decoded._id,
                    decoded.sessionToken,
                ],
            });

            if (!account) {
                res.status(401).json({
                    error: 'Invalid session.',
                });
                return;
            }

            req.user = {...account};
            next();
        } catch (err) {
            if (err.name && err.name === 'JsonWebTokenError') {
                res.status(401).json({
                    error: 'Your session is invalid. Please login again.',
                });
                return;
            }

            if (err.name && err.name === 'TokenExpiredError') {
                res.status(401).json({
                    error: 'Your session has expired. Please login again.',
                });
                return;
            }

            res.status(401).json({
                error: 'Invalid session.',
            });
        }
    };

    /**
     * Generate the HMAC SHA256 hash of a string
     * @param {String} string The plaintext string to hash
     * @return {String}        Base64 encoded string
     */
    hamcPassword(string) {
        // hash the password with SHA256, as bcrypt is limited to
        // 72 characters so we can still make use of the whole
        // string, should it exceed the limit.
        const passwordHMAC = forge.hmac.create();
        passwordHMAC.start('sha256', process.env.SECRETS_HMAC_KEY);
        passwordHMAC.update(string, 'utf8');
        return passwordHMAC.digest().toHex();
    }

    /**
     * Hashes and encrypts a password for storage
     * @param  {String} string The plaintext string
     * @return {String}        Base64 encoded string
     */
    async preparePassword(string) {
        const passwordHMAC = this.hamcPassword(string);

        // then hash the sha256 with bcrypt
        const finalPasswordHash = await bcrypt.hash(
            passwordHMAC,
            parseInt(process.env.SECURITY_PASSWORD_ROUNDS, 10)
        );

        // and encrypt the hash
        const encryptedPassword = await encrypt(finalPasswordHash);
        return forge.util.encode64(JSON.stringify(encryptedPassword));
    }

    /**
     * Checks if the passwords are the same
     * @param  {String} accountPassword The account's unencrypted password hash,
     *                                  from the database
     * @param  {String} string          The plaintext string to compare
     * @return {Boolean}
     */
    async verifyPassword(accountPassword, string) {
        try {
            if (validator.isEmpty(accountPassword) || validator.isEmpty(string)) {
                return false;
            }

            const passwordCipherData = forge.util.decode64(
                JSON.parse(accountPassword)
            );

            if (!passwordCipherData.iv || !passwordCipherData.cipherText) {
                return false;
            }

            const decryptedPasswordHMAC = await decrypt(
                passwordCipherData.cipherText,
                passwordCipherData.iv
            );

            const passwordHMAC = this.hamcPassword(string);

            return bcrypt.compare(passwordHMAC, decryptedPasswordHMAC);
        } catch (err) {
            return false;
        }
    }

    /**
     * Crete a new account with the provider
     * @param  {Request}  req           Express Request object
     * @param  {Object}   profile       User provider profile data
     * @param  {Function} callback
     */
    signupOauth = async (req, profile, callback) => {
        const provider = req.params.provider.toLowerCase();
        let userAccount;
        let userProfile;

        try {
            userAccount = new UserModel({
                email: mongoSanitizer(`no-email_${provider}-${profile.id}`),
            });

            await userAccount.save(); 

            userProfile = new ProviderModel({
                provider: mongoSanitizer(provider),
                profileId: mongoSanitizer(profile.id),
                userId: mongoSanitizer(userAccount._id),
            });
            await userProfile.save();
        } catch (err) {
            this.server.logger.error(err);

            if (userAccount && userAccount._id) {
                await UserModel.findByIdAndRemove(mongoSanitizer(userAccount._id));
            }

            if (userProfile && userProfile._id) {
                await ProviderModel.findByIdAndRemove(mongoSanitizer(userProfile._id));
            }

            callback(err);
            return;
        }

        callback(null, userAccount.toObject());
    }

    /**
     * Handles authentication requests from OAuth providers
     * @param  {Request}  req           Express Request object
     * @param  {String}   accessToken   OAuth access token
     * @param  {String}   refreshToken  OAuth refresh token
     * @param  {Object}   profile       User provider profile data
     * @param  {Function} callback
     */
    authenticateOAuth = async (req, accessToken, refreshToken, profile, callback) => {
        try {
            const providerName = req.params.provider.toLowerCase();

            const userProfile = await this.server.database.driver.query({
                sql: `SELECT
                            user_id,
                        FROM
                            providers
                        WHERE
                            provider = ?
                        AND
                            profile_id = ?
                        LIMIT
                            1`,
                values: [
                    providerName,
                    profile.id,
                ],
            });

            if (!userProfile || !userProfile.user_id) {
                // if they wanted to sign up, we instead create they account
                if (req.signedCookies) {
                    // but make sure the provider is the same
                    if (req.signedCookies['provider-signup'] === providerName) {
                        await this.signupOauth(req, profile, callback);
                        return;
                    }
                }

                callback(null, false, {error: 'No account is linked to this profile'});
                return;
            }

            const user = await this.server.database.driver.query({
                sql: `SELECT
                            id,
                            email,
                            sessionToken
                        FROM
                            accounts
                        WHERE
                            id = ?
                        LIMIT
                            1`,
                values: [
                    userProfile.user_id,
                ],
            });

            if (!user || !user.id) {
                callback(null, false, {error: 'Invalid login details.'});
                return;
            }

            // if success
            callback(null, {...user});
        } catch (err) {
            this.server.logger.error(err);
            callback(err);
        }
    }

    /**
     * Handles local authentication requests
     * @param  {String}   username The submitted username
     * @param  {String}   password The submitted password
     * @param  {Function} callback     Will pass on the result to passport
     */
    authenticateLocal = async (username, password, callback) => {
        try {
            const email = validator.stripLow('' + username, false).trim().toLowerCase();
            const password = '' + password;

            if (validator.isEmpty(email) || !validator.isEmail(email)) {
                res.status(400).json({error: 'Invalid login details.'});
                return;
            }

            const user = await this.server.database.driver.query({
                sql: `SELECT
                            id,
                            password,
                            sessionToken
                        FROM
                            accounts
                        WHERE
                            email = ?
                        LIMIT
                            1`,
                values: [
                    email,
                ],
            });

            if (!user || !user.id) {
                callback(null, false, {error: 'Invalid login details.'});
                return;
            }

            if (!this.verifyPassword(user.password, password)) {
                callback(null, false, {error: 'Invalid login details.'});
                return;
            }

            callback(null, {...user});
        } catch (err) {
            callback(err);
        }
    }

    /**
     * Crete a new account with the provider
     * @param  {Request}  req   Express Request object
     * @param  {Response} res   Express Response object
     * @param  {Function} callback
     */
    signupLocal = async (req, res) => {
        try {
            const email = validator.stripLow('' + req.body.username, false).trim().toLowerCase();
            const password = '' + req.body.password;

            if (validator.isEmpty(email) || !validator.isEmail(email)) {
                res.status(400).json({
                    error: 'Invalid email.',
                });
                return;
            }

            if (password.length < 8) {
                res.status(400).json({
                    error: 'Your password must be at least 8 characters long.',
                });
                return;
            }

            const found = await havePasswordBeenPwned(password);
            if (found) {
                res.status(400).json({
                    error: 'Your password appeared in the HIBP database. This means it was compromised in previous breach corpuses, and is no longer secure. Please choose another.',
                });
                return;
            }

            const preparedPassword = await this.preparePassword(password);

            const result = await this.server.database.driver.query({
                sql: `INSERT INTO
                            accounts
                            (
                                email,
                                password,
                                sessionToken
                            )
                        VALUES
                            (?,?,?)`,
                values: [
                    email,
                    preparedPassword,
                    uuid(),
                ],
            });

            if (!result || !result.insertId) {
                res.status(400).json({
                    error: 'The server was unable to handle your request. Please try again in a moment.',
                });
                return;
            }

            res.status(203).json({
                message: 'Your account was created!',
            });
        } catch (err) {
            if (err.code !== 'ER_DUP_ENTRY') {
                this.server.logger.error(err);

                res.status(400).json({
                    error: 'The server was unable to handle your request. Please try again in a moment.',
                });
            }

            res.status(400).json({
                error: 'An account is already signed up using that email address.',
            });
        }
    }
}

export default AuthMySQL;
