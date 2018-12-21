import passport from 'passport';
import LocalStrategy from 'passport-local';

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
        this.server = server;
    }

    /**
     * Setup an OAuth provider, assuming it is enabled
     * @param  {String} providerName name of the provider
     * @return {Promise}
     */
    async setupOAuthProvider(providerName) {
        if (process.env[`AUTH_METHOD_${providerName}_ENABLED`]) {
            return;
        }

        const packageName = process.env[`AUTH_METHOD_${providerName}_PASSPORT_PACKAGE`];
        const clientId = process.env[`AUTH_METHOD_${providerName}_CLIENT_ID`];
        const clientSecret = process.env[`AUTH_METHOD_${providerName}_CLIENT_SECRET`];
        const Strategy = require(`passport-${packageName}`).Strategy;

        if (!clientSecret) {
            this.server.logger.error(`The provider ${providerName} does not have a client secret set.`);
        }

        //setup the stategies we want
        this.passport.use(new Strategy({
            clientID: clientId,
            clientSecret: clientSecret,
            callbackURL: details.callbackUrl,
        }, this.authenticateOAuth));
    }

    /**
     * Setup local authentication provider
     */
    async setupLocalProvider() {
        //setup the stategies we want
        this.passport.use(new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
            failureFlash: false,
        }, this.authenticate));
    }

    /**
     * Handles authentication requests from OAuth providers
     * @param  {String}   accessToken  OAuth access token
     * @param  {String}   refreshToken OAuth refresh token
     * @param  {Object}   profile      User provider profile data
     * @param  {Function} callback
     */
    authenticateOAuth(accessToken, refreshToken, profile, callback) {
        // check if the user is in the database

        // if failed
        callback('Invalid authentication request.');
        return;

        // if successful
        callback(null, {
            user: {
                // user details
            },
        });
    }

    /**
     * Handles local authentication requests
     * @param  {String}   id       The submitted username, email or similar
     * @param  {String}   password The submitted password
     * @param  {Function} callback
     */
    authenticate(id, password, callback) {
        // check database for user and verify password

        // if failed
        callback('Invalid login details.');
        return;

        // if success
        callback(null, {
            user: {
                // user information here
            },
        });
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

        return Promise.all(providers);
    }
}

export default Authentication;
