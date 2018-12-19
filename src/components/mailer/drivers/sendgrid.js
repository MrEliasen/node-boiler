import Promise from 'bluebird';

/**
 * Sendgrid mailer class
 */
class Sendgrid {
    /**
     * Class constructor
     * @param  {logger} logger The application logger
     */
    constructor(logger) {
        this.logger = logger;
        this.sgMail = require('@sendgrid/mail');
        this.sgMail.setApiKey(process.env.MAIL_SENDGRID_API_KEY);
        Promise.promisify(this.sgMail.send);

        this.logger.notification(`Loaded "Sendgrid" mailer driver`);
    }

    /**
     * @param {Object} mailOptions The mail options
     */
    async sendMail(mailOptions) {
        await this.sgMail.sendAsync(mailOptions);
    }
}

export default Sendgrid;
