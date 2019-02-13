import validator from 'validator';
import mongoSanitizer from 'mongo-sanitize';
import Authentication from 'components/authentication/authentication';

// import database models
import UserModel from 'mongo-models/user';
import ProviderModel from 'mongo-models/provider';

// helper/security
import {havePasswordBeenPwned} from 'utils/security';
import {hmac256} from 'utils/helper';

/**
 * Authentication manager
 */
class AuthMongoDB extends Authentication {
    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        super(server);
        this.driverName = 'MongoDB';
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
            if (decoded.ip !== hmac256(req.ipInfo ? req.ipInfo.ipAddress : '') || decoded.agent !== hmac256(req.useragent.source)) {
                return null;
            }

            const user = await UserModel.findOne(
                {_id: mongoSanitizer(decoded.id), sessionToken: decoded.sessionToken},
                {_id: 1}
            );

            if (!user) {
                res.status(401).json({
                    error: 'Invalid session.',
                });
                return;
            }

            req.user = user.toObject();
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
}

export default AuthMongoDB;
