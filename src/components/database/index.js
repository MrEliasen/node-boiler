import mongoose from 'mongoose';

/**
 * Database manager
 */
class Database {
    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.name = 'Database';
        this.server = server;
    }

    /**
     * Loads auth strategies and enables passport
     */
    async load() {
        await this.connect();
        this.server.logger.notification(`[${this.name}] loaded component.`);
    }

    /**
     * Connect to the database
     */
    async connect() {
        try {
            mongoose.set('useCreateIndex', true);
            mongoose.set('useUnifiedTopology', true);

            // Connect to the MongoDB
            await mongoose.connect(
                process.env.DATABASE_URL,
                {
                    useNewUrlParser: true,
                }
            );

            this.server.logger.notification(`[${this.name}] connected.`);
        } catch (err) {
            this.server.logger.error(err);
        }
    }
}

export default Database;
