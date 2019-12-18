import bluebird from 'bluebird';
import redis from 'redis';
import {jsonSafeDecode} from '../../utils/helper';

bluebird.promisifyAll(redis);

/**
 * Cache manager
 */
class Cache {
    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.name = 'Cache';
        this.server = server;
    }

    /**
     * Loads auth strategies and enables passport
     * @return {Promise}     Resolves when done
     */
    load() {
        return new Promise(async (resolve) => {
            await this.connect();

            this.client.on('connect', () => {
                this.server.logger.notification(`[${this.name}] connected.`);
                this.server.logger.notification(`[${this.name}] loaded component.`);
                resolve();
            });

            this.client.on('error', (err) => {
                this.server.logger.error(err);
            });
        });
    }

    /**
     * Sorts out the redis connection string so it will work with node-redis
     * @return {Object} The redis url and options to use.
     */
    parseRedisSettings() {
        let options = null;
        let redisUrl = process.env.REDIS_URL;
        const domain = process.env.SERVER_FQDN;
        const keyLoc = `/etc/letsencrypt/live/${domain}/privkey.pem`;
        const certLoc = `/etc/letsencrypt/live/${domain}/cert.pem`;
        const chainLoc = `/etc/letsencrypt/live/${domain}/fullchain.pem`;

        if (redisUrl.includes('rediss://') && fs.existsSync(keyLoc)) {
            options = {
                tls: {
                    key: fs.readFileSync(keyLoc, 'utf8'),
                    cert: fs.readFileSync(certLoc, 'utf8'),
                    ca: [
                        fs.readFileSync(chainLoc, 'utf8'),
                    ],
                },
            };
        } else {
            redisUrl = redisUrl.replace('rediss://', 'redis://');
        }

        return {
            redisUrl,
            options,
        };
    }

    /**
     * Connect to the database
     */
    async connect() {
        try {
            const settings = this.parseRedisSettings();

            this.client = redis.createClient(
                settings.redisUrl,
                settings.redisOptions
            );
        } catch (err) {
            this.server.logger.error(err);
        }
    }

    /**
     * Caches data
     * @param {String} key   The unique key to cache the data under.
     * @param {Mixed} value  The data to cache.
     * @param {Number} ttl   How long (seconds) the data is cached for.
     * @return {Promise}     Resolves when done
     */
    async set(key, value, ttl = 300) {
        try {
            switch (typeof value) {
                case 'string':
                case 'number':
                case 'boolean':
                    break;

                default:
                    value = JSON.stringify(value);
                    break;
            }

            await this.client.setAsync(key, value, 'EX', ttl);
        } catch (error) {
            this.server.logger.error(error);
        }
    }

    /**
     * Get cached data
     * @param {String} key   The unique key of the cached data.
     * @return {Promise}     Resolves to the cached data or null
     */
    async get(key) {
        try {
            const data = await this.client.getAsync(key);
            return data ? jsonSafeDecode(data) : null;
        } catch (error) {
            this.server.logger.error(error);
        }
    }

    /**
     * Deletes cached data with key
     * @param {String} key   The unique key of the cached data.
     * @return {Promise}     Resolves when done
     */
    async delete(key) {
        try {
            await this.client.del(key);
        } catch (error) {
            this.server.logger.error(error);
        }
    }
}

export default Cache;
