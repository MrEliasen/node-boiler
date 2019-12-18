import path from 'path';
import dotenv from 'dotenv';
import Server from './components/server';

// load .env file
const dotloaded = dotenv.config();

if (dotloaded.error) {
    throw new Error(dotloaded.error);
}

new Server();
