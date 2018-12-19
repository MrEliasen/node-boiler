import fs from 'fs';

/**
 * https://gist.github.com/etalisoft/81280a2a1a312ca6aab91daa909ccba0
 */
class File {
    /**
     * class constructor
     * @param  {object} config Logger config
     * @param  {Object} loggerLevel The application log level
     * @param  {Object} logLevel    This logger's log level
     */
    constructor(config, loggerLevel, logLevel) {
        this.logType = 'File';
        this.logLevel = logLevel;
        this.loggerLevel = loggerLevel;
        this.file = config.file || './File.log';
        this.groupName = config.groupName || 'LOG:';
    }

    /**
     * Logs the args
     * @param  {[type]} options.args     [description]
     * @param  {[type]} options.fileName [description]
     * @param  {[type]} options.line     [description]
     * @param  {[type]} options.column   [description]
     * @return {[type]}                  [description]
     */
    log({args, fileName, line, column}) {
        return new Promise((resolve) => {
            if (this.loggerLevel < this.logLevel) {
                return resolve();
            }

            const {file, groupName} = this;
            const isArgObject = typeof arg === 'object';
            const fileInfo = `${fileName}:${line}:${column}`;
            const now = new Date().toLocaleString();
            const data = [`${groupName}\t${now}\t${fileInfo}`];
            const format = (arg) => (
                arg instanceof Error ? arg.stack : (isArgObject ? JSON.stringify(arg) : arg)
            );

            args.forEach((arg) => data.push(format(arg)));
            fs.appendFile(file, data.join('\n') + '\n', resolve);
        });
    }
}

export default File;
