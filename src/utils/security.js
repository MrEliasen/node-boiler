import request from 'request-promise';
import forge from 'node-forge';

/**
 * Have I Been Pwned - Password checker
 * @param  {String|Number} password The password to check
 * @return {Number} The number of times it appeared in the database
 */
export async function havePasswordBeenPwned(password) {
    try {
        const hash = forge.md.sha1.create();
        hash.update(password);
        const sha1 = hash.digest().toHex().toUpperCase();
        const prefix = sha1.substring(0, 5);

        const response = await request({
            uri: 'https://api.pwnedpasswords.com/range/' + prefix,
            headers: {
                'api-version': 2,
                'User-Agent': 'node-boilder-server',
            },
        });

        const found = response.split("\r\n").find((line) => {
            return (prefix + line).includes(sha1);
        });

        // if no entry was found, return 0 entries
        if (!found) {
            return 0;
        }

        return parseInt(found.split(':')[1]);
    } catch (err) {
        throw err;
    }
}

/**
 * Generates a random string or string of bytes of a given length
 * @param  {Number}  length The length in bytes
 * @param  {Boolean} toHex  Whether to convert the bytes to hex
 * @return {String|Binary}
 */
export async function getRandomBytes(length = 32, toHex = false) {
    const bytes = await forge.random.getBytes(32);
    return toHex ? forge.util.bytesToHex(bytes) : bytes;
}
/**
 * HMAC a value with a key
 * @param  {String} value   The value to HMAC
 * @param  {String} key     The key to sign with
 * @param  {String} cipher  The cipher to use
 * @return {String}
 */
export function hmac(value, key = null, cipher = 'sha1') {
    const hmac = forge.hmac.create();
    hmac.start(cipher, key || process.env.SECRETS_HMAC_KEY);
    hmac.update(value);
    return hmac.digest().toHex();
}

/**
 * Returns an MD5 Hash of a string
 * @param  {String} value The value to hash
 * @return {String}
 */
export function md5(value) {
    const md = forge.md.md5.create();
    md.update(value);
    return md.digest().toHex();
}

/**
 * Encrypt data using a global secret
 * @param  {String} payload String you want to encrypt
 * @return {Object} Generated IV and ciphertext
 */
export async function encrypt(payload) {
    try {
        const secret = forge.util.hexToBytes(
            process.env.SECRETS_ENCRYPTION_KEY
        );
        const iv = await forge.random.getBytes(32);
        const cipher = forge.cipher.createCipher('AES-CTR', secret);
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(payload, 'utf8'));
        cipher.finish();

        // return ciphertext, iv and salt
        return {
            cipherText: cipher.output.toHex(),
            iv: forge.util.bytesToHex(iv),
        };
    } catch (err) {
        throw err;
    }
}

/**
 * Decrypt data using a global secret
 * @param  {String} cipherText The cipher text you want to decrypt
 * @param  {String} iv         The IV for the cipher text
 * @return {String}            The plain text string
 */
export async function decrypt(cipherText, iv) {
    try {
        const secret = forge.util.hexToBytes(
            process.env.SECRETS_ENCRYPTION_KEY
        );
        const decipher = forge.cipher.createDecipher('AES-CTR', secret);
        decipher.start({iv: forge.util.hexToBytes(iv)});
        decipher.update(
            forge.util.createBuffer(
                forge.util.hexToBytes(cipherText)
            )
        );
        decipher.finish();

        return decipher.output.toString('utf8');
    } catch (err) {
        throw err;
    }
}
