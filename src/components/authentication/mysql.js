import validator from 'validator';
import express from 'express';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import uuid from 'uuid/v4';
import forge from 'node-forge';

// helper/security
import {havePasswordBeenPwned, decrypt, encrypt} from 'utils/security';
import {ucfirst} from 'utils/helper';

/**
 * Authentication manager
 */
class Authentication {
    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.name = 'authentication';
        this.routePrefix = '/auth';
        this.server = server;
        this.server.logger.notification(`[Authentication] instanciated "MySQL/MariaDB" authentication.`);
    }

    /**
     * Loads auth strategies and enables passport
     */
    async load() {
        this.passport = passport;
        this.server.app.use(this.passport.initialize());

        const enabledProviders = process.env.AUTH_METHOD_ENABLED;

        const providers = enabledProviders.split(',').map((providerName) => {
            providerName = providerName.toUpperCase();

            if (providerName === 'LOCAL') {
                return this.setupLocalProvider();
            }

            return this.setupOAuthProvider(providerName);
        });

        this.loadRoutes();
        await Promise.all(providers);

        this.server.logger.notification(`[Authentication] loaded on route prefix: ${this.routePrefix}.`);
    }

    /**
     * Load the auth routes
     */
    loadRoutes() {
        // setup API routes
        // eslint-disable-next-line
        this.routes = express.Router({
            caseSensitive: false,
        });

        const middleWare = (req, res, next) => {
            const provider = req.params.provider.toLowerCase();

            // check if they want to sign up or not
            if (`${this.routePrefix}/signup/${provider}` === req.originalUrl) {
                res.cookie('provider-signup', provider, {
                    maxAge: 1000 * 60 * 5,
                    httpOnly: true,
                    signed: true,
                });
            }

            this.passport.authenticate(
                provider,
                (err, user, info) => {
                    this.handleResponse(req, res, err, user, info);
                },
            )(req, res, next);
        };

        // provider signup and authentication
        this.routes.get('/login/:provider', middleWare);
        this.routes.get('/signup/:provider', middleWare);
        this.routes.get('/callback/:provider', middleWare);
        // local signup and authentication
        this.routes.post('/login/local', middleWare);
        this.routes.post('/signup/local', this.signupLocal);

        // register the routes to the /api prefix and version
        this.server.app.use(this.routePrefix, this.routes);
    }

    /**
     * Setup an OAuth provider, assuming it is enabled
     * @param  {String} providerName name of the provider
     * @return {Promise}
     */
    async setupOAuthProvider(providerName) {
        const packageName = process.env[
            `AUTH_METHOD_${providerName}_PASSPORT_PACKAGE`
        ];
        const clientId = process.env[
            `AUTH_METHOD_${providerName}_CLIENT_ID`
        ];
        const clientSecret = process.env[
            `AUTH_METHOD_${providerName}_CLIENT_SECRET`
        ];
        const Strategy = require(`passport-${packageName}`).Strategy;

        if (!clientSecret || !clientId) {
            this.server.logger.error(`The provider ${providerName} does not have a client secret or client id.`);
            return;
        }

        //setup the stategies we want
        this.passport.use(new Strategy({
            clientID: clientId,
            clientSecret: clientSecret,
            callbackURL: `${process.env.BASE_URL}/auth/callback/${providerName.toLowerCase()}`,
            passReqToCallback: true,
        }, this.authenticateOAuth));

        this.server.logger.notification(`[Authentication] loaded authentication strategy "${ucfirst(providerName.toLowerCase())}"`);
    }

    /**
     * Setup local authentication provider
     */
    async setupLocalProvider() {
        //setup the stategies we want
        this.passport.use(new LocalStrategy({
            usernameField: process.env.AUTH_METHOD_LOCAL_USERNAME_FIELD,
            passwordField: process.env.AUTH_METHOD_LOCAL_PASSWORD_FIELD,
            session: false,
            failureFlash: false,
        }, this.authenticateLocal));

        this.server.logger.notification(`[Authentication] loaded authentication strategy: "Local"`);
    }

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

    /**
     * handles authentication reponses
     * @param  {Request} req Express Request object
     * @param  {Response} res Express Response object
     * @param  {Error} err Error object if exists
     * @param  {object} user the user details from the auth method
     * @param  {Object} info Express Response object
     */
    handleResponse(req, res, err, user, info) {
        if (err) {
            this.server.logger.error(err);
            res.status(400).json(info || {error: 'Invalid login request.'});
        }

        if (err || !user) {
            res.status(400).json(info);
            return;
        }

        jwt.sign(
            {
                user,
                ip: req.ipInfo ? req.ipInfo.ipAddress : '',
                agent: req.useragent.source,
            },
            process.env.SECRETS_SIGNING_KEY,
            {
                expiresIn: process.env.AUTH_SESSION_TTL,
            },
            (err, token) => {
                if (err) {
                    this.server.logger.error(err);
                    res.status(400).json({
                        error: 'The server was unable to handle your request. Please try again in a moment.',
                    });
                    return;
                }

                res.json({jwt: token});
            }
        );
    }
}

export default Authentication;
