import bluebird from 'bluebird';
import mailer from 'nodemailer';

/**
 * SMTP mailer class
 */
class SMTP {
    /**
     * Class constructor
     * @param  {Server} server The server object
     */
    constructor(server) {
        this.name = 'SMTP';
        this.server = server;

        this.mailer = mailer.createTransport({
            host: process.env.MAIL_SMTP_HOST,
            port: process.env.MAIL_SMTP_PORT,
            auth: {
                user: process.env.MAIL_SMTP_USER,
                pass: process.env.MAIL_SMTP_PASSWORD,
            },
        });
        bluebird.promisify(this.mailer.sendMail);
    }

    /**
     * https://nodemailer.com/usage/#sending-mail
     * @param  {String|Array}   to      The user(s) to send to
     * @param  {String}         subject Email subject
     * @param  {String}         message HTML/Text
     */
    async send(to, subject, message) {
        if (!Array.isArray(to)) {
            await this.mailer.sendMailAsync({
                from: process.env.MAIL_SENDER,
                to: to,
                subject: subject,
                html: message,
            });
            return;
        }

        await Promise.all(to.map((recipient) => {
            return this.mailer.sendMailAsync({
                from: process.env.MAIL_SENDER,
                to: recipient,
                subject: subject,
                html: message,
            });
        }));
    }
}

export default SMTP;
