import Sendgrid from './drivers/sendgrid';
import MailToLog from './drivers/file';
import SMTP from './drivers/smtp';

/**
 * Mailer
 */
class Mailer {
    /**
     * Class constructor
     * @param  {Server} server  Server instance
     */
    constructor(server) {
        this.name = 'Mailer';
        this.server = server;
    }

    /**
     * Loads the mailing solutions
     * @return {Promise}
     */
    async load() {
        try {
            switch (process.env.MAIL_DRIVER) {
                case 'sendgrid':
                    this.driver = new Sendgrid(this.server);
                    break;

                case 'file':
                    this.driver = new MailToLog(this.server);
                    break;

                case 'smtp':
                    this.driver = new SMTP(this.server);
                    break;
            }

            this.server.logger.notification(`[${this.name}] "${this.driver.name}" driver loaded.`);
            this.server.logger.notification(`[${this.name}] loaded component.`);
        } catch (err) {
            this.server.logger.error(err);
        }
    }

    /**
     * Send mail using the loaded driver
     * @param  {String|Array}   to      The user(s) to send to
     * @param  {String}         subject Email subject
     * @param  {String}         message HTML/Text
     * @return {Promise}
     */
    async send(to, subject, message) {
        await this.driver.send(to, subject, message);
    }
}

export default Mailer;
