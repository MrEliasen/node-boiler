import path from 'path';
import http from 'http';
import express from 'express';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import filter from 'content-filter';
import passport from 'passport';
import geoip from 'geoip-lite';
import useragent from 'express-useragent';

import Mailer from 'components/mailer';
import Logger from 'components/logger';
import Database from 'components/database';

/**
 * Server Class
 */
class Server {
    /**
     * Class constructor
     */
    constructor() {
        this.boot();
        // holds any extensions of the server, included from the load() method
        this.extensions = [];
    }

    /**
     * Boot up the server
     * @return {Promise}
     */
    async boot() {
        this.logger = new Logger(this);
        this.mailer = new Mailer(this);
        this.database = new Database(this);

        await this.database.connect();

        // https expected to be proxied with Nginx or Dokku.
        this.app = express();
        this.webServer = http.createServer(this.app);

        // bind the logger and mailer to our app
        this.app.set('logger', this.logger);
        this.app.set('mailer', this.mailer);

        // Trust only the local proxy
        this.app.set('trust proxy', 'loopback');
        this.app.use(bodyParser.json());
        this.app.use(bodyParser.urlencoded({
            extended: true,
        }));
        this.app.use(express.json({limit: '5000kb'}));
        this.app.use(helmet());
        this.app.use(useragent.express());
        this.app.use(filter({
            methodList: [
                'GET',
                'POST',
                'PATCH',
                'DELETE',
            ],
        }));

        this.app.use(passport.initialize());

        // Set needed headers for the application.
        this.app.use(this.middlewareHeaders);

        // GEO IP lookup
        this.app.use(this.middlewareGeoIP);

        // load custom extension
        await this.loadExtension('example', 'example');

        // set static files directory
        this.app.use(express.static(path.join(__dirname, '../../../public')));

        // 404 page
        this.app.get('*', function(req, res) {
            res.status(404).send('Page not found');
        });

        // listen on port 80
        this.webServer.listen(process.env.PORT);
        this.logger.notification(`Server listening on port ${process.env.PORT}`);
    }

    /**
     * Loads an extension of the server
     * @param  {String} filePath The path to the file to include
     * @param  {String} name     The name of the extension (alphanumerical)
     */
    async loadExtension(filePath, name) {
        try {
            const extensionDir = path.join(__dirname, '../../extensions/');
            const Extension = require(extensionDir + filePath);

            if (Extension.default) {
                this.extensions[name] = new Extension.default(this);
            } else {
                this.extensions[name] = new Extension(this);
            }

            // wait for the extension to finish loading
            await this.extensions[name].load();

            let urlPrefix = '';
            // if the extension adds routes, we include the urlprefix if found
            if (this.extensions[name].urlPrefix) {
                urlPrefix = `(route prefix: ${this.extensions[name].urlPrefix})`;
            }

            this.logger.notification(`[Extensions] "${name}" loaded ${urlPrefix}`);
        } catch (err) {
            this.logger.notification(`[Extensions] Failed to load the extension "${name}"`);
            this.logger.error(err);
        }
    }

    /**
     * Outputs required headers in responses
     * @param  {Request}    req     Express Request Object
     * @param  {Response}   res     Express Response Object
     * @param  {Function}   next
     */
    middlewareHeaders(req, res, next) {
        // Website you wish to allow to connect
        res.setHeader(
            'Access-Control-Allow-Origin',
            '*'
        );
        // Request methods you wish to allow
        res.setHeader(
            'Access-Control-Allow-Methods',
            'GET, POST, PATCH, DELETE, OPTIONS'
        );
        // Request headers you wish to allow
        res.setHeader(
            'Access-Control-Allow-Headers',
            'Authorization, Accept, X-Requested-With, Content-Type'
        );
        // Whether requests needs to include cookies in the requests
        // sent to the API. We shouldn't use this unless we retained
        // sessions etc. which we don't!
        res.setHeader( 'Access-Control-Allow-Credentials', false);

        // Pass to next middleware
        next();
    }

    /**
     * Attaches Geo IP data to all requests
     * @param  {Request}    req     Express Request Object
     * @param  {Response}   res     Express Response Object
     * @param  {Function}   next
     */
    middlewareGeoIP = (req, res, next) => {
        try {
            const xForwardedFor = ('' + req.get('x-forwarded-for')).replace(/:\d+$/, '');
            const ip = xForwardedFor || req.get('cf-connecting-ip') ||req.connection.remoteAddress || req.get('x-real-ip');
            const geoipInfo = this.getIpInfo(ip);

            console.log(req.ip);
            console.log(req.ips);

            req.ipInfo = {
                ipAddress: ip || 'Unknown',
                city: 'Unknown',
                country: 'Unknown',
                ...geoipInfo,
            };

            next();
        } catch (err) {
            if (process.env.NODE_ENV !== 'production') {
                next();
                return;
            }

            this.logger.warn(err);
            res.status(401).json({
                status: 400,
                message: 'Missing required headers',
            });
        }
    }

    /**
     * Get Geo information for a given IP
     * @param  {String} ip IP address
     * @return {Object}
     */
    getIpInfo = (ip) => {
        // IPV6 addresses can include IPV4 addresses
        // So req.ip can be '::ffff:86.3.182.58'
        // However geoip-lite returns null for these
        if (ip.includes('::ffff:')) {
            ip = ip.split(':').reverse()[0];
        }

        if (ip === '127.0.0.1' || ip === '::1') {
            throw new Error('This won\'t work on localhost');
        }

        const lookedUpIP = geoip.lookup(ip);

        if (!lookedUpIP) {
            throw new Error('Unable to lookup IP addresses.');
        }

        return lookedUpIP;
    }
}

export default Server;
