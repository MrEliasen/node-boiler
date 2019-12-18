# Node Boiler Plate

A resonable flexible node boiler plate. Not overly packed with features, I try to keep it resonably bloat free.

## Requirements

* Node (Tested using v10)
* A MongoDB (I recommend [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) (they have a free tier).
* Redis (needed for caching, and scaling web sockets with pub/sub).

## Installation

1. Clone or download repository
2. Run `yarn/npm install`
3. Rename `.env-example` to `.env`
    - Make any necessary changes to the .env file. The "Secrets" are mandatory, and should be 64 characters long.
4. Run `yarn/npm run dev`

## Serving

To deploy:

1. Transpile the code `yarn/npm run build` (yarn might encounter some issues if you use nvm)
2. Serve it `yarn/npm run start`

## API Endpoints

**Login**

- Endpoint: `/auth/login`
- Method: `POST`
- Payload: `username,password`

**Sign Up**

- Endpoint: `/auth/signup`
- Method: `POST`
- Payload: `username,password`

## Socket Events (Client)

**Authenticate**
Authenticates the socket using the JWT returned from the login API call. This will add the user object to the socket client on the server-side, allowing you to check who the socket belongs to, example: `socket.user = {_id: .., username: ..., etc..}`.

- eventName: `authenticate`
- args: `<string> JWT`