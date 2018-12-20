import path from 'path';
import http from 'http';
import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import helmet from 'helmet';
import filter from 'content-filter';
import passport from 'passport';
import geoip from 'geoip-lite';
import useragent from 'express-useragent';

import Mailer from 'components/mailer';
import Logger from 'components/logger';

/**
 * Server Class
 */
class Server {
    /**
     * Class constructor
     */
    constructor() {
        this.boot();
    }

    /**
     * Boot up the server
     * @return {Promise}
     */
    async boot() {
        this.logger = new Logger();
        this.mailer = new Mailer(this.logger);

        await this.dbConnect();

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

        // favicon
        this.app.get('/favicon.ico', function(req, res) {
            res.sendFile(path.join(__dirname, '../../static/favicon.ico'));
        });

        // 404 page
        this.app.get('*', function(req, res) {
            res.sendFile(path.join(__dirname, '../../static/404.html'));
        });

        // listen on port 80
        this.webServer.listen(process.env.PORT);
        this.logger.notification(`Server listening on port ${process.env.PORT}`);
    }

    /**
     * Connect to the database
     */
    async dbConnect() {
        mongoose.set('useCreateIndex', true);
        // Connect to the MongoDB
        await mongoose.connect(
            process.env.DATABASE_HOST,
            {
                useNewUrlParser: true,
            }
        );
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
