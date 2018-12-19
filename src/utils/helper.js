import path from 'path';
import Logger from 'components/logger';

/**
 * Uppercases the first letter in a string
 * @param {String} string
 * @return {String}
 */
export function ucfirst(string) {
    string = '' + string;
    return string.charAt(0).toUpperCase() + string.substr(1, string.length);
}

/**
 * Formats a number to 2 decimal points
 * @param  {Number} number The number to format
 * @return {Number}
 */
export function round2Decimal(number) {
    return Math.max(0, Math.round(number * 100) / 100);
}

/**
 * Escape a string for use in shell (not for security)
 * @param  {String} arg The string to escape
 * @return {String}
 */
export function shellEscape(arg) {
    return arg.replace(/(["\s'$`\(\)\\])/g, '\\$1');
}

/**
 * Artificual delay
 * @param  {Number} ms Timer in MS
 * @return {Promise}
 */
export function timer(ms) {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve();
        }, ms);
    });
}

/**
 * Generates a random value between min and max
 * @param  {Number} min
 * @param  {Number} max
 * @return {Number}
 */
export function numberBetween(min, max) {
    min = parseInt(min, 10);
    max = parseInt(max, 10);

    if (isNaN(min) || isNaN(max)) {
        return 0;
    }

    return Math.floor(
        (Math.random() * (
            Math.max(min, max) - Math.min(min, max)
        )) + Math.min(min, max)
    );
}

/**
 * Generates a logger instance to be used throughout the app
 * @param  {String} level   The logging level
 * @return {Logger} Instance of the Logger component
 */
export function newLogger(level = null) {
    const rootPath = path.join(__dirname, '..');

    // set default level based on NODE_ENV if not set
    if (!level) {
        level = process.env.NODE_ENV === 'production' ? 'error' : 'info';
    }

    // setup the logger
    return new Logger({
        level: level,
        debugFile: `${rootPath}/logs/debug.log`,
        infoFile: `${rootPath}/logs/info.log`,
        warnFile: `${rootPath}/logs/warn.log`,
        errorFile: `${rootPath}/logs/error.log`,
    });
}
