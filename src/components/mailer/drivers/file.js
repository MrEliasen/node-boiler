import fs from 'fs';
import mkdirp from 'mkdirp';
import path from 'path';

const render = (to, subject, message) => (
    `<!--
    To: ${to}
    Subject: ${subject}
    Send Date: ${new Date().toString()}
-->
${message}`);

/**
 * Sendgrid mailer class
 */
export default class File {
    /**
     * Class constructor
     * @param  {Server} server The server object
     */
    constructor(server) {
        this.name = 'File';
        this.server = server;
        this.createOutputDir(process.env.MAIL_FILE_PATH);
    }

    /**
     * Create the output directory, recursively, for the emails.
     * @param {String} outputPath The output path for the email html files
     */
    createOutputDir(outputPath) {
        this.outputPath = path.join(__dirname, '../../../../', outputPath);
        mkdirp.sync(this.outputPath, {mode: '0755'});
    }

    /**
     * Saves the email details to file
     * @param  {String|Array}   to      The user(s) to send to
     * @param  {String}         subject Email subject
     * @param  {String}         message HTML/Text
     */
    async send(to, subject, message) {
        const fileName = path.join(
            this.outputPath,
            new Date().toISOString().replace(/[^0-9Z]+/g, '-')
        ).slice(0, -1);

        if (Array.isArray(to)) {
            to = to.join(', ');
        }

        await fs.writeFile(`${fileName}.html`, render(to, subject, message));
    }
}
