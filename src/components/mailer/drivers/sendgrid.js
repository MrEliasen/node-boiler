import bluebird from 'bluebird';
import sendGrid from '@sendgrid/mail';
bluebird.promisify(sendGrid.send);
bluebird.promisify(sendGrid.sendMultiple);

/**
 * Sendgrid mailer class
 */
class Sendgrid {
    /**
     * Class constructor
     * @param  {Server} server The server object
     */
    constructor(server) {
        this.name = 'SendGrid';
        this.server = server;

        // load API key
        sendGrid.setApiKey(process.env.MAIL_SENDGRID_API_KEY);
    }

    /**
     * https://www.npmjs.com/package/@sendgrid/mail#quick-start-hello-email
     * @param {Object} mailOptions The mail options
     */
    async send(mailOptions) {
        await sendGrid.sendAsync(mailOptions);
    }

    /**
     * Send email
     * @param  {String|Array}   to      The user(s) to send to
     * @param  {String}         subject Email subject
     * @param  {String}         message HTML/Text
     */
    send(to, subject, message) {
        try {
            const email = {
                to: to,
                from: process.env.SENDGRID_FROM,
                subject: subject,
                content: [
                    {
                        type: 'text/html',
                        value: message,
                    },
                ],
            };

            if (Array.isArray(email.to)) {
                sendGrid.sendMultipleAsync(email);
                return;
            }

            sendGrid.sendAsync(email);
        } catch (err) {
            this.server.logger.error(err);
        }
    }
}

export default Sendgrid;
