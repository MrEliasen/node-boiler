/**
 * Decodes a string, returns string original string or json object if decoded.
 * @param {String} string
 * @return {String}
 */
export function jsonSafeDecode(string) {
    try {
        const json = JSON.parse(string);
        return json;
    } catch (err) {
        return string;
    }
}

/**
 * Decodes a string, returns string original string or json object if decoded.
 * @param {String} payload
 * @return {String}
 */
export function jsonSafeEncode(payload) {
    try {
        return JSON.stringify(payload);
    } catch (err) {
        return payload;
    }
}

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
