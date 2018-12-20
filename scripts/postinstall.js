require('babel-core/register');
require('babel-polyfill');

import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import {execSync} from 'child_process';

// utilities
import {shellEscape} from 'utils/helper';
import Logger from 'components/logger';

// Root path of our application
const rootPath = path.join(__dirname, '..');
// escaped version of the root path, used in shell below
const rootShellPath = shellEscape(rootPath);
const logger = new Logger();

// create the logs dir if it does not exists
logger.notification('Generating log direcotry');
const logsDirPath = `${rootPath}/logs`;
if (!fs.existsSync(logsDirPath)) {
    fs.mkdirSync(logsDirPath);
}

// Setup .env file is not found
const envFilePath = `${rootPath}/.env`;
if (!fs.existsSync(envFilePath)) {
    logger.notification('Missing .env file, generating..');
    execSync(`cp -n ${rootShellPath}/.env-sample ${rootShellPath}/.env`);
} else {
    logger.notification('.env file found, skipping..');
}

// generate a signing key
try {
    logger.notification('Generating keys..');

    // load the config
    let configData = fs.readFileSync(envFilePath, {encoding: 'utf8'});

    // Generate session signing key if needed
    if (configData.includes('SECRETS_SIGNING_KEY=""')) {
        logger.notification('Generating signing key..');
        const signingKey = crypto.randomBytes(32).toString('hex');
        configData = configData.replace(
            'SECRETS_SIGNING_KEY=""',
            `SECRETS_SIGNING_KEY="${signingKey}"`
        );
    } else {
        logger.notification('Skipping signing key, already exists.');
    }

    // Generate encryption key if needed
    if (configData.includes('SECRETS_ENCRYPTION_KEY=""')) {
        logger.notification('Generating encryption key..');
        const encryptionKey = crypto.randomBytes(32).toString('hex');
        configData = configData.replace(
            'SECRETS_ENCRYPTION_KEY=""',
            `SECRETS_ENCRYPTION_KEY="${encryptionKey}"`
        );
    } else {
        logger.notification('Skipping encryption key, already exists.');
    }

    // Generate HMAC key if needed
    if (configData.includes('SECRETS_HMAC_KEY=""')) {
        logger.notification('Generating HMAC key..');
        const hmacKey = crypto.randomBytes(32).toString('hex');
        configData = configData.replace(
            'SECRETS_HMAC_KEY=""',
            `SECRETS_HMAC_KEY="${hmacKey}"`
        );
    } else {
        logger.notification('Skipping HMAC key, already exists.');
    }

    // Generate password storage encryption key if needed
    if (configData.includes('SECRETS_PASSWORD_KEY=""')) {
        logger.notification('Generating pass encryption key..');
        const passwordKey = crypto.randomBytes(32).toString('hex');
        configData = configData.replace(
            'SECRETS_PASSWORD_KEY=""',
            `SECRETS_PASSWORD_KEY="${passwordKey}"`
        );
    } else {
        logger.notification('Skipping pass encryption key, already exists.');
    }

    fs.writeFileSync(envFilePath, configData);
} catch (err) {
    logger.error(err);
}
