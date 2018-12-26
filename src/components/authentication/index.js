import express from 'express';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import jwt from 'jsonwebtoken';

// import database models
import UserModel from 'mongo-models/user';
import ProviderModel from 'mongo-models/provider';

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
        return Promise.all(providers);
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
        this.routes.post('/signup/local', middleWare);

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
                email: `no-email_${provider}-${profile.id}`,
            });

            await userAccount.save(); 

            userProfile = new ProviderModel({
                provider: provider,
                profileId: profile.id,
                userId: userAccount._id,
            });
            await userProfile.save();
        } catch (err) {
            this.server.logger.error(err);

            if (userAccount && userAccount._id) {
                await UserModel.findByIdAndRemove(userAccount._id);
            }

            if (userProfile && userProfile._id) {
                await ProviderModel.findByIdAndRemove(userProfile._id);
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
                    provider: providerName,
                    profileId: profile.id,
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
                {_id: userProfile.userId},
                {email: 1, password: 1, sessionToken: 1}
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
                {email: username},
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
