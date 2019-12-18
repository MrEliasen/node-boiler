import path from 'path';
import chalk from 'chalk';
import ConsoleLogger from './methods/console';
import FileLogger from './methods/file';
import Notification from './methods/notification';

/**
 * Original logger code by etalisoft
 * https://gist.github.com/etalisoft/81280a2a1a312ca6aab91daa909ccba0
 */
class Logger {
    /**
     * Class constructor
     * @param  {Server} server Server instance
     * @param  {Object} config Configuration options
     */
    constructor(server, config = {}) {
        const levels = [
            'debug',
            'info',
            'warn',
            'error',
        ];

        const rootPath = path.join(__dirname, '../../..');

        config = {
            level: process.env.NODE_ENV !== 'production' ? 'info' : 'error',
            debugFile: `${rootPath}/logs/debug.log`,
            infoFile: `${rootPath}/logs/info.log`,
            warnFile: `${rootPath}/logs/warn.log`,
            errorFile: `${rootPath}/logs/error.log`,
            ...config,
        };
        const level = levels.indexOf(config.level);

        // create console loggers
        const consoleDebug = new ConsoleLogger(
            {
                groupName: 'DEBUG:',
                method: 'debug',
                color: chalk.blue,
            },
            levels.indexOf('debug'),
            level
        );
        const consoleInfo = new ConsoleLogger(
            {
                groupName: 'LOG:',
                method: 'info',
                color: chalk.reset,
            },
            levels.indexOf('info'),
            level
        );
        const consoleWarn = new ConsoleLogger(
            {
                groupName: 'WARN:',
                method: 'warn',
                color: chalk.yellow,
            },
            levels.indexOf('warn'),
            level
        );
        const consoleError = new ConsoleLogger(
            {
                groupName: 'ERROR:',
                method: 'error',
                color: chalk.red,
            },
            levels.indexOf('error'),
            level
        );
        const consoleFatal = new ConsoleLogger(
            {
                groupName: 'FATAL:',
                method: 'error',
                color: chalk.purple,
            },
            levels.indexOf('error'),
            level
        );

        // create file loggers
        const fileDebug = new FileLogger(
            {
                groupName: 'DEBUG:',
                file: config.debugFile,
            },
            levels.indexOf('debug'),
            level
        );
        const fileInfo = new FileLogger(
            {
                groupName: 'INFO:',
                file: config.infoFile,
            },
            levels.indexOf('info'),
            level
        );
        const fileWarn = new FileLogger(
            {
                groupName: 'WARN:',
                file: config.warnFile,
            },
            levels.indexOf('warn'),
            level
        );
        const fileError = new FileLogger(
            {
                groupName: 'ERROR:',
                file: config.errorFile,
            },
            levels.indexOf('error'),
            level
        );
        const fileFatal = new FileLogger(
            {
                groupName: 'FATAL:',
                file: config.errorFile,
            },
            levels.indexOf('error'),
            level
        );

        // system notitications
        const notification = new Notification();

        // save actions to perform on a logging event
        this.actions = {
            consoleInfo,
            consoleDebug,
            consoleWarn,
            consoleError,
            consoleFatal,
            fileInfo,
            fileDebug,
            fileWarn,
            fileError,
            fileFatal,
        };

        // create the individual loggers with the console and file loggers
        this.debug = this.run(consoleDebug, fileDebug);
        this.info = this.run(consoleInfo, fileInfo);
        this.warn = this.run(consoleWarn, fileWarn);
        this.error = this.run(consoleError, fileError);
        this.fatal = this.run(consoleFatal, fileFatal);
        this.notification = this.run(notification);

        this.notification(`[Logger] the logger was setup with log-level "${config.level}"`);
    }

    /**
     * Parse the logger arguments into promises
     * @param  {...Args} args
     * @return {Object}
     */
    parse(...args) {
        // NOTE: Node doesn't supply Error.fileName and Error.lineNumber
        // So we have to try to dig it out of the current stacktrace
        const stackFrame = new Error().stack.split('\n')[3] || '';
        const regFile = /\((.+):(\d+):(\d+)\)/;
        const [, fileName, line, column] = stackFrame.match(regFile) || [];

        return {args, fileName, line, column};
    }

    /**
     * setup the actual loggers
     * @param  {...Args} actions
     * @return {Function}
     */
    run(...actions) {
        return (...args) => {
            if (process.env.NODE_ENV === 'test') {
                return;
            }

            const data = this.parse(...args);
            return Promise.all(actions.map((action) => action.log(data)));
        };
    }
}

export default Logger;
