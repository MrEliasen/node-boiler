import express from 'express';

/**
 * Example of how to extend the server
 * @param  {Server} server The server instance
 */
class Example {
    /**
     * Class constructor
     * @param  {Server} server The app server instance
     */
    constructor(server) {
        this.server = server;
        this.urlPrefix = '/example';
    }

    /**
     * Loads the extension bits
     */
    async load() {
        // setup API routes
        // eslint-disable-next-line
        this.routes = express.Router({
            caseSensitive: false,
        });

        // user Routes
        this.routes.route('/test')
            .get((req, res) => {
                res.send({hello: 'world'});
            });
        // route requiring authentication
        this.routes.route('/test')
            .get(this.server.authentication.middleWareIsLoggedIn, (req, res) => {
                res.send({hello: req.user});
            });

        // register the routes to the /api prefix and version
        this.server.app.use(this.urlPrefix, this.routes);
    }
};

export default Example;

