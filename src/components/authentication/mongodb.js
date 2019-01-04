import validator from 'validator';
import mongoSanitizer from 'mongo-sanitize';
import express from 'express';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import jwt from 'jsonwebtoken';

// import database models
import UserModel from 'mongo-models/user';
import ProviderModel from 'mongo-models/provider';

// helper/security
import {havePasswordBeenPwned} from 'utils/security';
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
        this.server.logger.notification(`[Authentication] instanciated "MongoDB" authentication.`);
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
            const userProfile = await ProviderModel.findOne(
                {
                    provider: mongoSanitizer(providerName),
                    profileId: mongoSanitizer(profile.id),
                },
                {userId: 1}
            );

            if (!userProfile) {
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

            const user = await UserModel.findOne(
                {_id: mongoSanitizer(userProfile.userId)},
                {_id: 1, email: 1, sessionToken: 1}
            );

            if (!user) {
                callback(null, false, {error: 'Invalid login details.'});
                return;
            }

            // if success
            callback(null, user.toObject());
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
            const user = await UserModel.findOne(
                {email: mongoSanitizer(username)},
                {email: 1, password: 1, sessionToken: 1}
            );

            if (!user) {
                callback(null, false, {error: 'Invalid login details.'});
                return;
            }

            if (!user.verifyPassword(password)) {
                callback(null, false, {error: 'Invalid login details.'});
                return;
            }

            // if success
            callback(null, user.toObject());
        } catch (err) {
            callback(err);
            return;
        }
    }

    /**
     * Crete a new account with the provider
     * @param  {Request}  req   Express Request object
     * @param  {Response} res   Express Response object
     * @param  {Function} callback
     */
    async signupLocal(req, res) {
        let email = validator.stripLow('' + req.body.username, false).trim().toLowerCase();
        let password = '' + req.body.password;

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

        const user = new UserModel({
            email,
            password,
        });

        try {
            await user.save();

            res.status(203).json({
                message: 'Your account was created!',
            });
        } catch (err) {
            if (err.code !== 11000) {
                this.server.logger.error(err);

                res.status(400).json({
                    error: 'An error occurred while creating your account. Please try again in a moment.',
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

                res.json({jwt: token, user});
            }
        );
    }
}

export default Authentication;
