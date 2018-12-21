import mongoose from 'mongoose';

/**
 * MongoDB Database Driver
 */
class MongoDB {
    /**
     * Class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.name = 'mongodb';
        this.server = server;
    }

    /**
     * Load the database driver
     */
    async connect() {
        try {
            mongoose.set('useCreateIndex', true);
            // Connect to the MongoDB
            await mongoose.connect(
                process.env.DATABASE_MONGODB_HOST,
                {
                    useNewUrlParser: true,
                }
            );
        } catch (err) {
            this.server.logger.error(err);
        }
    }
}

export default MongoDB;
