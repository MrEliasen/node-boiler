import mysql from 'promise-mysql';
import validator from 'validator';
import Promise from 'bluebird';
import fs from 'fs';

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
        this.connection = null;
    }

    /**
     * Load the database driver
     */
    async connect() {
        try {
            this.connection = await mysql.createConnection({
                host: process.env.DATABASE_MYSQL_HOST,
                user: process.env.DATABASE_MYSQL_USER,
                password: process.env.DATABASE_MYSQL_PASSWORD,
                database: process.env.DATABASE_MYSQL_DATABASE,
                port: process.env.DATABASE_MYSQL_PORT,
            });

            await this.setup();
        } catch (err) {
            this.server.logger.error(err);
        }
    }

    /**
     * Load the database driver
     */
    async setup() {
        try {
            const tables = fs.readFileSync(__dirname + '/tables.sql', 'utf8');

            await Promise.all(tables.split(';').map((table) => {
                table = validator.stripLow(table, false);

                if (validator.isEmpty(table)) {
                    return true;
                }

                return this.connection.query(table);
            }));
        } catch (err) {
            this.server.logger.error(err);
        }
    }

    /**
     * Send an SQL query to the database
     * @param  {...Object} args The params to send to the query
     * @return {Promise}
     */
    async query(...args) {
        try {
            args = args[0];

            // if there is no timeout, set one
            if (!args.timeout) {
                args.timeout = 5000; // 5 seconds
            }

            //https://github.com/mysqljs/mysql#preparing-queries ??
            const result = await this.connection.query(args);

            if (Array.isArray(result)) {
                switch (result.length) {
                    case 0:
                        return null;

                    case 1:
                        return result[0];
                }
            }

            return result;
        } catch (err) {
            throw err;
        }
    }

    // transactions: https://www.npmjs.com/package/mysql#transactions
}

export default MySQL;
