import Err from '@openaddresses/batch-error';
import jwt from 'jsonwebtoken';
import { CookieJar, Cookie } from 'tough-cookie';
import { CookieAgent } from 'http-cookie-agent/undici';

/**
 * Authentication Middleware
 * @class
 *
 * @param {Object} opts Options Object
 * @param {String} opts.secret Signing Secret
 * @param {String} opts.unsafe Use unsafe Signing Secret
 * @param {String} [opts.group] LDAP Group to ensure user is a member of
 * @param {String} opts.api WebTak Marti API to authenticate against
 */
export default class AuthenticationMiddleware {
    constructor(opts) {
        this.name = 'Login Blueprint';
        this.secret = opts.secret;
        this.unsafe = opts.unsafe;
        this.api = opts.api;
        this.group = opts.group;
    }

    async blueprint(router) {
        await router.post('/login', {
            name: 'Create Login',
            group: 'Login',
            body: {
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
        }, async (req, res) => {
            try {
                const url = new URL('/oauth/token', this.api);
                url.searchParams.append('grant_type', 'password');
                url.searchParams.append('username', req.body.username);
                url.searchParams.append('password', req.body.password);

                const authres = await fetch(url);

                if (!authres.ok) {
                    throw new Err(500, new Error(await authres.text()), 'Non-200 Response from Auth Server - Token');
                }

                const body = await authres.json();

                if (body.error === 'invalid_grant' && body.error_description.startsWith('Bad credentials')) {
                    throw new Err(400, null, 'Invalid Username or Password');
                } else if (body.error || !body.access_token) {
                    throw new Err(500, new Error(body.error_description), 'Unknown Login Error');
                }

                if (this.group) {
                    const url = new URL('/Marti/api/groups/all', this.api);

                    const jar = new CookieJar();
                    await jar.setCookie(new Cookie({
                        key: 'access_token',
                        value: body.access_token
                    }), this.api);

                    const agent = new CookieAgent({ cookies: { jar } });

                    const groupres = await fetch(url, {
                        credentials: 'include',
                        dispatcher: agent
                    });

                    if (!groupres.ok) {
                        throw new Err(500, new Error(await authres.text()), 'Non-200 Response from Auth Server - Groups');
                    }

                    const gbody = await groupres.json();

                    const groups = gbody.data.map((d) => {
                        return d.name
                    });

                    if (!groups.includes(this.group)) {
                        throw new Err(403, null, 'Insufficient Group Privileges');
                    }
                }

                return res.json({
                    token: jwt.sign({ access: 'user' }, this.secret)
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

                try {
                    try {
                        const decoded = jwt.verify(authorization[1], this.secret);
                        req.auth = decoded;
                    } catch (err) {
                        if (this.unsafe) {
                            const decoded = jwt.verify(authorization[1], this.unsafe);
                            req.auth = decoded;
                        } else {
                            throw err;
                        }
                    }
                } catch (err) {
                    return Err.respond(new Err(401, err, 'Invalid Token'), res);
                }
            } else if (req.query.token) {
                const token = req.query.token;

                try {
                    try {
                        const decoded = jwt.verify(token, this.secret);
                        req.token = decoded;
                    } catch (err) {
                        if (this.unsafe) {
                            const decoded = jwt.verify(token, this.unsafe);
                            req.token = decoded;
                        } else {
                            throw err;
                        }
                    }
                } catch (err) {
                    return Err.respond(new Err(401, err, 'Invalid Token'), res);
                }
            } else {
                req.auth = false;
            }

            return next();
        });

        await router.get('/login', {
            name: 'Get Login',
            group: 'Login',
            res: {
                type: 'object',
                required: ['access'],
                properties: {
                    access: {
                        type: 'string'
                    }
                }
            }
        }, (req, res) => {
            try {
                return res.json(req.auth);
            } catch (err) {
                Err.respond(err, res);
            }
        });

    }
}
