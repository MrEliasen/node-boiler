import io from 'socket.io';
import bluebird from 'bluebird';
import redis from 'redis';
import {jsonSafeEncode, jsonSafeDecode} from '../../utils/helper';
bluebird.promisifyAll(redis);

/**
 * Socket manager
 */
class Socket {
    namespace = '/socket';

    /**
     * class constructor
     * @param  {Server} server Server instance
     */
    constructor(server) {
        this.name = 'Socket';
        this.server = server;
    }

    /**
     * Loads setup IO
     */
    async load() {
        const settings = this.server.cache.parseRedisSettings();

        // setup connection to redis and subscribe to messages from other servers 
        this.pub = redis.createClient(settings.redisUrl, settings.options);
        this.sub = redis.createClient(settings.redisUrl, settings.options);
        this.sub.subscribe('cluster');

        // Listen for messages being published to this server.
        this.sub.on('message', this.onClusterMessage);

        // error handling
        this.pub.on('error', (err) => {
            this.server.logger.error(err);
        });
        this.sub.on('error', (err) => {
            this.server.logger.error(err);
        });

        this.socketServer = io(this.server.webserver, {
            maxHttpBufferSize: 153600,
            path: this.namespace,
            pingTimeout: 5000,
            pingInterval: 7500,
        });

        this.loadRoutes();
        this.server.logger.notification(`[${this.name}] loaded component.`);
    }

    /**
     * Handle messages from other servers in the cluster
     * @param  {Mixed}  payload The message payload
     * @param  {String} channel The sub/sub channel
     */
    publish(payload, channel = 'cluster') {
        this.pub.publish(channel, jsonSafeEncode(payload));
    }

    /**
     * Handle messages from other servers in the cluster
     * @param  {String} channel The name of the channel
     * @param  {String} payload The message payload
     */
    onClusterMessage = (channel, payload) => {
        try {
            const message = jsonSafeDecode(payload);

            if (message.broadcast) {
                this.socketServer.emit(message.event, message.payload);
                return;
            }

            this.socketServer.to(message.channel).emit(message.event, message.payload);
        } catch (err) {
            this.server.logger.error(err);
        }
    }

    /**
     * Load the socket routes
     */
    loadRoutes() {
        this.socketServer.on('connection', async (socket) => {
            // socket connection
            socket.on('disconnect', () => {
                this.handleDisconnect(socket);
            });

            // socket authentication
            socket.on('req auth', (token) => {
                this.server.auth.authenticateSocket(socket, token);
            });
            socket.on('req logout', () => {
                socket.user = null;
            });
        });
    }

    /**
     * Handles client disconnections
     * @param  {Socket} socket  Client socket object
     */
    handleDisconnect(socket) {
        if (!socket.channel) {
            return;
        }
    }

    /**
     * Broadcast an event to all connected clients
     * @param  {String} eventName The name of the event
     * @param  {Array|String|Object} payload   The payload of the event
     */
    toEveryone = (eventName, payload) => {
        // send message to all other servers in the cluster
        this.publish({
            broadcast: true,
            event: eventName,
            payload: payload,
        });
    }

    /**
     * Broadcast an event to all connected clients in a channel
     * @param  {String} channelName The name of the channel
     * @param  {String} eventName   The name of the event
     * @param  {Array|String|Object} payload   The payload of the event
     */
    toChannel = (channelName, eventName, payload) => {
        // send message to all other servers in the cluster
        this.publish({
            broadcast: false,
            channel: channelName,
            event: eventName,
            payload: payload,
        });
    }
}

export default Socket;
