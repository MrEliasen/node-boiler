import express from 'express';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import jwt from 'jsonwebtoken';

// helper/security
import {ucfirst, hmac256} from 'utils/helper';

// drivers
import drivers from './drivers';

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
        await Promise.all(providers);

        this.server.logger.notification(`[Authentication] using "${this.driverName}" driver.`);
        this.server.logger.notification(`[Authentication] route prefix: ${this.routePrefix}.`);
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
                ip: hmac256(req.ipInfo ? req.ipInfo.ipAddress : ''),
                agent: hmac256(req.useragent.source),
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
