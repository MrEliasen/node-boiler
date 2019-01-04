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
        this.server = server;

        try {
            switch (process.env.MAIL_DRIVER) {
                case 'sendgrid':
                    this.driver = new Sendgrid(this.server.logger);
                    break;

                case 'file':
                    this.driver = new MailToLog(this.server.logger);
                    break;

                case 'smtp':
                    this.driver = new SMTP(this.server.logger);
                    break;
            }

            this.server.logger.notification(`[Mailer] "${this.driver.name}" driver loaded.`);
        } catch (err) {
            this.server.logger.error(err);
        }
    }

    /**
     * Send mail using the loaded driver
     * @param  {Object} mailOptions The mailer options
     * @return {Promise}
     */
    async send(mailOptions) {
        await this.driver.send(mailOptions);
    }
}

export default Mailer;
