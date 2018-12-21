import mysql from 'mysql';
import Promise from 'bluebird';

// create async functions of all the mysql methods
Promise.promisifyAll(mysql);

/**
 * MySQL Database Driver
 */
class MySQL {
    /**
     * Class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.name = 'mysql';
        this.server = server;
    }

    /**
     * Load the database driver
     */
    async connect() {
        try {
            this.connection = mysql.createConnection({
                host: process.env.DATABASE_MYSQL_HOST,
                user: process.env.DATABASE_MYSQL_USER,
                password: process.env.DATABASE_MYSQL_PASSWORD,
                database: process.env.DATABASE_MYSQL_DATABASE,
                port: process.env.DATABASE_MYSQL_PORT,
            });
            await this.connection.connectAsync();
        } catch (err) {
            this.server.logger.error(err);
        }
    }
}

export default MySQL;
