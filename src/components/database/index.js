import drivers from './drivers';
/**
 * Database manager
 */
class Database {
    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.server = server;
        this.driver = null;
    }

    /**
     * Load the database driver
     */
    async connect() {
        try {
            this.driver = new drivers[process.env.DATABASE_DRIVER](this.server);
            await this.driver.connect();
            this.server.logger.notification(`[Database] "${this.driver.name}" driver loaded.`);
        } catch (err) {
            this.server.logger.error(err);
        }
    }
}

export default Database;
