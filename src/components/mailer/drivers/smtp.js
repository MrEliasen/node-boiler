import Promise from 'bluebird';
import mailer from 'nodemailer';

/**
 * SMTP mailer class
 */
class SMTP {
    /**
     * Class constructor
     * @param  {logger} logger The application logger
     */
    constructor(logger) {
        this.logger = logger;

        this.mailer = mailer.createTransport({
            host: process.env.MAIL_SMTP_HOST,
            port: process.env.MAIL_SMTP_PORT,
            auth: {
                user: process.env.MAIL_SMTP_USER,
                pass: process.env.MAIL_SMTP_PASSWORD,
            },
        });
        Promise.promisify(this.mailer.send);
        this.logger.notification(`Loaded "SMTP" mailer driver`);
    }

    /**
     * @param {Object} mailOptions The mail options
     */
    async sendMail(mailOptions) {
        await this.mailer.sendAsync(mailOptions);
    }
}

export default SMTP;
