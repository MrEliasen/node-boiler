import request from 'request-promise';
import forge from 'node-forge';
import jwt from 'jsonwebtoken';

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
 * Generates an JWT with the specified data, and TTL
 * @param  {Object} data   The object to store in the jwt
 * @param  {String} expire The TTL of the token (eg. 7d or 1h)
 * @return {String} the generated JWT
 */
export function createJWT(data, expire = null) {
    return new Promise((resolve, reject) => {
        jwt.sign(
            data,
            process.env.AUTH_SIGNING_SECRET,
            {expiresIn: expire || process.env.AUTH_SESSION_TTL},
            (err, token) => {
                if (err) {
                    reject(err);
                    return;
                }

                resolve(token);
            }
        );
    });
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
