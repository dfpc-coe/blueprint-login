import Err from '@openaddresses/batch-error';

/**
 * Authentication Middleware
 * @class
 *
 * @param {Object} opts Options Object
 * @param {String} opts.secret
 * @param {String} opts.username
 * @param {String} opts.password
 */
export default class AuthenticationMiddleware {
    constructor(opts) {
        this.name = 'Login Blueprint';
        this.secret = opts.secret;
        this.username = opts.username;

        // TODO: This is temproary for now until LDAP is set up
        // Don't use unencrypted passwords in production - bcrypt is absolutely required
        this.password = opts.password;
    }

    async blueprint(router, config) {
        await router.post('/login', {
            name: 'Create Login',
            group: 'Login',
            req: {
                type: 'object',
                required: ['username', 'password'],
                properties: {
                    username: {
                        type: 'string'
                    },
                    password: {
                        type: 'string'
                    }
                }
            },
            res: {
                type: 'object',
                required: ['token'],
                properties: {
                    token: {
                        type: 'string'
                    }
                }
            }
        }, (req, res) => {
            try {
                if (
                    req.body.username !== this.username
                    || req.body.password !== this.password
                ) {
                    throw new Err(401, null, 'Invalid Credentials');
                }

                return res.json({
                    token: '123'
                });
            } catch (err) {
                Err.respond(err, res);
            }
        });

        router.router.use((req, res, next) => {
            if (req.header('authorization')) {
                const authorization = req.header('authorization').split(' ');

                if (authorization[0].toLowerCase() !== 'bearer') {
                    return res.status(401).json({
                        status: 401,
                        message: 'Only "Bearer" authorization header is allowed'
                    });
                }

                if (!authorization[1]) {
                    return res.status(401).json({
                        status: 401,
                        message: 'No bearer token present'
                    });
                }

                if (authorization[1] === config.SigningSecret) {
                    req.auth = {
                        access: 'machine'
                    };
                } else {
                    req.auth = false;
                }
            } else {
                req.auth = false;
            }

            return next();
        });
    }
}
