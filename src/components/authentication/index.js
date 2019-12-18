import express from 'express';
import jwt from 'jsonwebtoken';
import sanitize from 'mongo-sanitize';
import validator from 'validator';
import argon2 from 'argon2';
import forge from 'node-forge';
import moment from 'moment-timezone';
import {body, validationResult} from 'express-validator/check';
import AccountModel from '../database/models/account';

// helper/security
import {
    havePasswordBeenPwned,
    decrypt,
    encrypt,
    getRandomBytes,
} from '../../utils/security';

/**
 * Authentication manager
 */
class Authentication {
    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.name = 'Authentication';
        this.routePrefix = '/auth';
        this.server = server;
    }

    /**
     * Loads auth strategies and enables passport
     */
    async load() {
        this.loadRoutes();
        this.server.logger.notification(`[${this.name}] route prefix: ${this.routePrefix}.`);
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

        // local signup and authentication
        this.routes.post('/login',
            [
                body('username').isLength({min: 2}),
                body('password').isLength({
                    min: process.env.PASSWORD_MINLEN,
                    max: process.env.PASSWORD_MAXLEN
                }),
            ],
            this.middlewareCheckForErrors,
            this.login
        );
        this.routes.post('/signup',
            [
                body('username').isLength({min: 2}),
                body('password').isLength({
                    min: process.env.PASSWORD_MINLEN,
                    max: process.env.PASSWORD_MAXLEN
                }),
            ],
            this.middlewareCheckForErrors,
            this.createAccount
        );

        // register the routes to the /api prefix and version
        this.server.app.use(this.routePrefix, this.routes);
    }

    /**
     * Check if the validator middleware returned an error
     * @param  {Request} req Express request object
     * @param  {Response} res Express response object
     * @param  {Next} next Express next function
     */
    middlewareCheckForErrors(req, res, next) {
        // Finds the validation errors in this request
        // and wraps them in an object with handy functions
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            res.status(422).json({
                errors: errors.array(),
            });
            return;
        }

        next();
    }

    /**
     * Will check barer token header and assign the user to req.user
     * @param  {Request}  req   Express Request object
     * @param  {Response} res   Express Response object
     * @param  {Function} next  Express next/callback
     */
    middleware = async (req, res, next) => {
        try {
            const authorization = '' + req.get('Authorization');

            if (!authorization) {
                res.status(401).json({
                    error: 'Missing authentication token.',
                });
                return;
            }

            const token = authorization.replace('Bearer ', '');
            const decodedToken = await this.validateToken(token);

            if (!decodedToken) {
                res.status(401).json({
                    error: 'Invalid authentication token.',
                });
                return;
            }

            const account = await AccountModel.findOne({
                _id: decodedToken.id,
                session_token: decodedToken.session,
            });

            if (!account) {
                res.status(401).json({
                    error: 'Invalid authentication token.',
                });
                return;
            }

            req.user = account.toObject();
            next();
        } catch (err) {
            if (err.name && err.name === 'JsonWebTokenError') {
                res.status(401).json({
                    error: 'Invalid authentication token.',
                });
                return;
            }

            if (err.name && err.name === 'TokenExpiredError') {
                res.status(401).json({
                    error: 'Your session has expired.',
                });
                return;
            }

            this.server.logger.error(err);
            res.status(401).json({
                error: 'Invalid authentication token.',
            });
        }
    };

    /**
     * Handles local authentication requests
     * @param  {Request}  req   Express request object
     * @param  {Response} res   Express response object
     */
    login = async (req, res) => {
        try {
            const username = req.body.username;
            const password = req.body.password;

            const account = await AccountModel.findOne({
                username: sanitize(username),
            });

            if (!account) {
                res.status(401).json({
                    error: 'Invalid login details',
                });
                return;
            }

            const isValidPassword = await this.verifyPassword(
                account.password,
                password
            );

            if (!isValidPassword) {
                res.status(401).json({
                    error: 'Invalid login details',
                });
                return;
            }

            jwt.sign(
                {
                    id: userAccount._id.toString(),
                    session: userAccount.session_token,
                },
                process.env.SECRETS_SIGNING_KEY,
                {
                    expiresIn: process.env.AUTH_TOKEN_TTL,
                },
                (err, token) => {
                    if (err) {
                        throw err;
                    }

                    res.status(200).json(token);
                }
            );
        } catch (err) {
            this.server.logger.error(err);
            res.status(500).json({
                error: 'We encountered an error while trying to log you in. Please try again a moment.',
            });
        }
    }

    /**
     * Crete a new account with the provider
     * @param  {Request}  req   Express Request object
     * @param  {Response} res   Express Response object
     * @param  {Function} callback
     */
    createAccount = async (req, res) => {
        try {
            const username = req.body.username || '';
            const password = req.body.password || '';

            if (validator.isEmpty(username) || validator.isEmpty(password)) {
                res.status(400).json({
                    error: 'Please fill out all the required details.',
                });
                return;
            }

            // Check if password is pwned
            const found = await havePasswordBeenPwned(password);
            if (found) {
                res.status(400).json({
                    error: 'Your password appeared in the HIBP database. This means it was compromised in previous breach corpuses, and is no longer secure. Please choose another. For more information visit https://haveibeenpwned.com/Passwords',
                });
                return;
            }

            // prepare the password for storage in the database
            const preparedPassword = await this.preparePassword(password);
            const sessionKey = await getRandomBytes(64, true);

            const newAccount = new AccountModel({
                username: sanitize(username),
                password: preparedPassword,
                session_key: sessionKey,
                created_date: moment().utc().toDate(),
            });

            // save in the database.
            await newAccount.save();

            res.status(203).json({
                message: 'Account',
            });
        } catch (err) {
            if (err.code !== 11000) {
                this.server.logger.error(err);

                res.status(500).json({
                    error: 'The server was unable to handle your request. Please try again in a moment.',
                });
                return;
            }

            res.status(400).json({
                error: 'An account is already signed up using that username.',
            });
        }
    }

    /**
     * Hashes and encrypts a password for storage
     * @param  {String} string The plaintext string
     * @return {String}        Base64 encoded string
     */
    async preparePassword(string) {
        try {
            // then hash the password with argon2
            const finalPasswordHash = await argon2.hash(string, {
                type: argon2[process.env.PASSWORD_HASH_TYPE],
                memoryCost: process.env.PASSWORD_HASH_MEMORY_COST,
                timeCost: process.env.PASSWORD_HASH_TIME_COST,
                parallelism: process.env.PASSWORD_HASH_PARALLELISM,
                hashLength: process.env.PASSWORD_HASH_LENGTH,
            });

            // and encrypt the hash
            const encryptedPassword = await encrypt(finalPasswordHash);
            return forge.util.encode64(JSON.stringify(encryptedPassword));
        } catch (err) {
            this.server.logger.error(err);
        }
    }

    /**
     * Checks if the passwords are the same
     * @param  {String} password The account's unencrypted password hash,
     *                                  from the database
     * @param  {String} string          The plaintext string to compare
     * @return {Boolean}
     */
    async verifyPassword(password, string) {
        try {
            // check if the supplied password is empty
            if (validator.isEmpty(string) || validator.isEmpty(password)) {
                return false;
            }

            const passwordCipherData = JSON.parse(
                forge.util.decode64(password)
            );

            if (!passwordCipherData.iv || !passwordCipherData.cipherText) {
                return false;
            }

            const decryptedPasswordHMAC = await decrypt(
                passwordCipherData.cipherText,
                passwordCipherData.iv
            );

            return argon2.verify(decryptedPasswordHMAC, string);
        } catch (err) {
            return false;
        }
    }

    /**
     * Checks if a JWT is valid
     * @param  {String} token The token string
     * @return {Promise}
     */
    validateToken(token) {
        return new Promise((resolve) => {
            try {
                jwt.verify(
                    token,
                    process.env.SECRETS_SIGNING_KEY,
                    (err, decoded) => {
                        resolve(decoded);
                    }
                );
            } catch (error) {
                return resolve(null);
            }
        });
    }
}

export default Authentication;
