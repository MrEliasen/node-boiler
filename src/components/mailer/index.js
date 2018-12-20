import Sendgrid from './drivers/sendgrid';
import MailToLog from './drivers/file';
import SMTP from './drivers/smtp';

/**
 * Mailer
 */
class Mailer {
    /**
     * Class constructor
     * @param  {Logger} logger The application logger
     */
    constructor(logger) {
        try {
            switch (process.env.MAIL_DRIVER) {
                case 'sendgrid':
                    this.driver = new Sendgrid(logger);
                    break;

                case 'file':
                    this.driver = new MailToLog(logger);
                    break;

                case 'smtp':
                    this.driver = new SMTP(logger);
                    break;
            }
        } catch (err) {
            logger.error(err);
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
