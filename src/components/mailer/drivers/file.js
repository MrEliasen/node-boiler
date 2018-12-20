import fs from 'fs';
import mkdirp from 'mkdirp';
import path from 'path';

const render = (mailOptions) => (
    `<!--
    From: ${mailOptions.from}
    To: ${mailOptions.to}
    Subject: ${mailOptions.subject}
    Send Date: ${new Date().toString()}
-->
${mailOptions.html}`);

/**
 * Sendgrid mailer class
 */
export default class File {
    /**
     * Class constructor
     * @param  {logger} logger The application logger
     */
    constructor(logger) {
        this.logger = logger;
        this.createOutputDir(process.env.MAIL_FILE_PATH);
        this.logger.notification(`Loaded "File" mailer driver`);
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
     * @param {Object} mailOptions The mail options
     */
    async send(mailOptions) {
        const fileName = path.join(
            this.outputPath,
            new Date().toISOString().replace(/[^0-9Z]+/g, '-')
        ).slice(0, -1);

        await fs.writeFile(`${fileName}.html`, render(mailOptions));
    }
}
