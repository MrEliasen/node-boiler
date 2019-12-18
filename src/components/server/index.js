import http from 'http';
import express from 'express';
import helmet from 'helmet';
import bodyParser from 'body-parser';
import filter from 'content-filter';
import cors from 'cors';

// Core components
import Logger from '../logger';
import Database from '../database';

// Function components
import Cache from '../cache';
import Mailer from '../mailer';
import Authentication from '../authentication';
import Socket from '../socket';

/**
 * Server Class
 */
class Server {
    /**
     * Class constructor
     * @param  {Boolean} autoBoot Whether the server should auto boot or not.
     */
    constructor(autoBoot = true) {
        this.components = {};

        if (autoBoot) {
            this.boot();
        }
    }

    /**
     * Boot up the server
     * @return {Promise}
     */
    async boot() {
        // https expected to be proxied with Nginx or Dokku.
        this.app = express();
        this.webserver = http.createServer(this.app);

        // load core components
        this.logger = new Logger(this);
        this.database = new Database(this);
        this.cache = new Cache(this);
        this.mailer = new Mailer(this);
        this.authentication = new Authentication(this);
        this.auth = this.authentication; // a shorthand of the auth component.
        this.socket = new Socket(this);

        process.on('uncaughtException', async (err) => {
            this.logger.error(err);
        });

        // enable basic security
        this.app.use(helmet());
        this.app.use(filter({
            methodList: [
                'GET',
                'PUT',
                'POST',
                'PATCH',
                'DELETE',
            ],
        }));

        // you probably won't need raw parser.
        /*this.app.use(bodyParser.raw({
            inflate: true,
            limit: '5mb',
            type: 'text/plain',
        }));*/
        // set http body limits
        this.app.use(bodyParser.urlencoded({
            limit: '5mb',
            extended: true,
        }));
        this.app.use(bodyParser.json({
            limit: '5mb',
        }));
        this.app.use(express.json({
            limit: '5mb',
        }));

        // Set needed headers for the application.
        this.app.options('*', cors());
        this.app.use(cors());

        // bind the logger
        this.app.set('logger', this.logger);

        // Trust only the local proxy
        this.app.set('trust proxy', 'loopback');

        // parse and find the connecting user's IP
        this.app.use(this.getConnectionIP);

        await this.database.load();
        await this.cache.load();
        await this.mailer.load();
        await this.auth.load();
        await this.socket.load();

        // listen on port 80
        this.webserver.listen(process.env.PORT);
        this.logger.notification(`[Server] listening on port ${process.env.PORT}`);
    }

    /**
     * Find the connection IP
     * @param  {Request}  req  Express Request object
     * @param  {Response} res  Express Response object
     * @param  {Function} next Express "next" function
     */
    getConnectionIP = (req, res, next) => {
        try {
            const remoteIp = req.connection.remoteAddress;
            let pseudoRealIp = remoteIp;

            // check for proxy headers and cloudflare
            const proxyHeader = req.get('X-Forwarded-For');
            const cfHeader = req.get('CF-Connecting-IP');

            if (proxyHeader || cfHeader) {
                pseudoRealIp = cfHeader || proxyHeader;
            }

            // IPV6 addresses can include IPV4 addresses
            // So req.ip can be '::ffff:86.3.182.58'
            if (remoteIp.includes('::ffff:')) {
                pseudoRealIp = remoteIp.split(':').reverse()[0];
            }

            if (process.env.NODE_ENV !== 'development') {
                if (pseudoRealIp === '127.0.0.1' || pseudoRealIp === '::1') {
                    res.status(400).json({
                        error: 'You cannot connect from a local IP',
                    });
                    return;
                }
            }

            req.pseudoRealIp = pseudoRealIp;
            next();
        } catch (err) {
            this.logger.error(err);
            res.status(500).json({
                error: 'Unable to process you request.',
            });
        }
    }
}

export default Server;
