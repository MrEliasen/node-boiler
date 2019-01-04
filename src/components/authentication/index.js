// drivers
import drivers from './drivers';

export default function(server) {
    return new drivers[process.env.DATABASE_DRIVER](server);
}