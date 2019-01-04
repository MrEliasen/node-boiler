# Node Boiler Plate

Node Boiler Plate

## Requirements

* Node (recommend v10.14.2 LTS or later)
* A MongoDB (I recommend [MongoDB Atlas](https://www.mongodb.com/cloud/atlas). They have a free tier.)

## Installation

1. Clone or download repository
3. Run `yarn install`
4. Make any necessary changes to the .env file
5. Run `yarn run dev`

## Serving

To deploy:

1. Transpile the code `yarn run build` or `npm run build` (yarn might encounter some issues if you use nvm)
2. Serve it `yarn run start`

## Development

In `src/components/server`, inside the `boot` method, we are loading in the "example" extension, which is found in `src/extensions`.

```javascript
async boot() {
    ...
    // GEO IP lookup
    this.app.use(this.middlewareGeoIP);

    // load custom extension
    await this.loadExtension('example', 'example'); // <------- HERE!
    ...
}
```

The server object, from which you should be able to access any part of the application, is always passed on to all loaded extensions as the first parameter.

List of some of the common things you might want to access from the server object:

| Members  | Type | Description | More info|
| --- | --- | --- | --- |
| `server.logger` | _{Object}_ | the logger component. | [docs](https://github.com/MrEliasen/node-boiler/wiki/Logger) |
| `server.database` | _{Object}_ | the database component. | see docs |
| `server.mailer` | _{Object}_ | the mailer component. | [docs](https://github.com/MrEliasen/node-boiler/wiki/Mailer) |
| `server.extensions` | _{Array}_ | the array of loaded extensions. | see docs |
| `server.app` | _{Object}_ | the express application. | see docs |
| `server.webserver` | _{Object}_ | the HTTP/s web server. | see docs |
| `server.authentication` | _{Object}_ | The authentication & sign up component. | see docs |
