import chalk from 'chalk';

/**
 * https://gist.github.com/etalisoft/81280a2a1a312ca6aab91daa909ccba0
 */
class Notification {
    /**
     * Logs the args.
     * @param  {[type]} options.args     [description]
     * @param  {[type]} options.fileName [description]
     * @param  {[type]} options.line     [description]
     * @param  {[type]} options.column   [description]
     * @return {[type]}                  [description]
     */
    log({args, fileName, line, column}) {
        return new Promise((resolve) => {
            console.log(
                chalk.keyword('green')('==> '),
                chalk.keyword('yellow')(args)
            );
            resolve();
        });
    }
}

export default Notification;
