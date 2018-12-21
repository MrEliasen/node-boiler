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
        this.name = 'SendGrid';
        this.logger = logger;
        this.sgMail = require('@sendgrid/mail');
        this.sgMail.setApiKey(process.env.MAIL_SENDGRID_API_KEY);
        Promise.promisify(this.sgMail.send);
    }

    /**
     * https://www.npmjs.com/package/@sendgrid/mail#quick-start-hello-email
     * @param {Object} mailOptions The mail options
     */
    async send(mailOptions) {
        await this.sgMail.sendAsync(mailOptions);
    }
}

export default Sendgrid;
