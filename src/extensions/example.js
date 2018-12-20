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
        this.load();
    }

    /**
     * Loads the extension bits
     */
    load() {
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

        // register the routes to the /api prefix and version
        this.server.app.use('/example', this.routes);
    }
};

export default Example;

