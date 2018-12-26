import express from 'express';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import jwt from 'jsonwebtoken';

// import database models
import UserModel from 'mongo-models/user';

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

        this.routes.post('/login/:provider',
            (req, res, next) => {
                this.passport.authenticate(
                    req.params.provider.toLowerCase(),
                    (err, user, info) => {
                        this.handleResponse(req, res, err, user, info);
                    },
                )(req, res, next);
            }
        );
        // register the routes to the /api prefix and version
        this.server.app.use(this.routePrefix, this.routes);
    }

    /**
     * Setup an OAuth provider, assuming it is enabled
     * @param  {String} providerName name of the provider
     * @return {Promise}
     */
    async setupOAuthProvider(providerName) {
        const packageName = process.env[`AUTH_METHOD_${providerName}_PASSPORT_PACKAGE`];
        const clientId = process.env[`AUTH_METHOD_${providerName}_CLIENT_ID`];
        const clientSecret = process.env[`AUTH_METHOD_${providerName}_CLIENT_SECRET`];
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
     * Handles authentication requests from OAuth providers
     * @param  {String}   accessToken  OAuth access token
     * @param  {String}   refreshToken OAuth refresh token
     * @param  {Object}   profile      User provider profile data
     * @param  {Function} callback
     */
    authenticateOAuth(accessToken, refreshToken, profile, callback) {
        try {
            //do stuff
            done(null, {accessToken, refreshToken, profile});
        } catch (err) {
            done(err);
            return;
        }
    }

    /**
     * Handles local authentication requests
     * @param  {String}   username The submitted username
     * @param  {String}   password The submitted password
     * @param  {Function} done     Will pass on the result to passport
     */
    async authenticateLocal(username, password, done) {
        try {
            const user = await UserModel.findOne(
                {email: username},
                {email: 1, password: 1, sessionToken: 1}
            );

            if (!user) {
                done(null, false, {error: 'Invalid login details.'});
                return;
            }

            if (!user.verifyPassword(password)) {
                done(null, false, {error: 'Invalid login details.'});
                return;
            }

            // if success
            done(null, user.toObject());
        } catch (err) {
            done(err);
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
        }

        if (err || !user) {
            res.status(400).json(info);
            return;
        }

        jwt.sign(
            {
                user,
                ip: req.ipInfo.ipAddress,
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
