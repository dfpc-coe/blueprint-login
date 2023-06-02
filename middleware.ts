import Err from '@openaddresses/batch-error';
import jwt from 'jsonwebtoken';
import { CookieJar, Cookie } from 'tough-cookie';
import { CookieAgent } from 'http-cookie-agent/undici';
import { Request, Response, NextFunction } from 'express';

export interface ConfigOpts {
    secret: string;
    unsafe?: string;
    api: string;
    group?: string;
}

export interface AuthRequest extends Request {
    token?: {
        access: string;
    },
    auth: {
        access: string;
    }
}

/**
 * Authentication Middleware
 * @class
 *
 * @param opts Options Object
 * @param opts.secret Signing Secret
 * @param opts.unsafe Use unsafe Signing Secret
 * @param [opts.group] LDAP Group to ensure user is a member of
 * @param opts.api WebTak Marti API to authenticate against
 */
export default class AuthenticationMiddleware {
    name: string;
    secret: string;
    unsafe: string | null;
    api: string;
    group?: string | null;

    constructor(opts: ConfigOpts) {
        this.name = 'Login Blueprint';
        this.secret = opts.secret;
        this.unsafe = opts.unsafe || null;
        this.api = opts.api;
        this.group = opts.group || null;
    }

    async blueprint(router: any) {
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
        }, async (req: Request, res: Response) => {
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
                    // @ts-ignore - dispatcher is not yet supported
                        dispatcher: agent
                    });

                    if (!groupres.ok) {
                        throw new Err(500, new Error(await authres.text()), 'Non-200 Response from Auth Server - Groups');
                    }

                    const gbody: {
                        data: Array<{
                            name: string;
                        }>
                    }= await groupres.json();

                    const groups = gbody.data.map((d: {
                        name: string
                    }) => {
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

        router.router.use((req: AuthRequest, res: Response, next: NextFunction) => {
            if (req.header && typeof req.header('authorization')) {
                const authorization = (req.header('authorization') || '').split(' ');

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
                        if (typeof decoded === 'string') throw new Err(400, null, 'Decoded JWT Should be Object');
                        req.auth = {
                            access: decoded.access ? decoded.access : 'unknown'
                        };
                    } catch (err) {
                        if (this.unsafe) {
                            const decoded = jwt.verify(authorization[1], this.unsafe);
                            if (typeof decoded === 'string') throw new Err(400, null, 'Decoded JWT Should be Object');
                            req.auth = {
                                access: decoded.access ? decoded.access : 'unknown'
                            };
                        } else {
                            throw err;
                        }
                    }
                } catch (err: any) {
                    return Err.respond(new Err(401, err, 'Invalid Token'), res);
                }
            } else if (req.query && req.query.token && typeof req.query.token === 'string') {
                const token = req.query.token;

                try {
                    try {
                        const decoded = jwt.verify(token, this.secret);
                        if (typeof decoded === 'string') throw new Err(400, null, 'Decoded JWT Should be Object');
                        req.token = {
                            access: decoded.access ? decoded.access : 'unknown'
                        };
                    } catch (err) {
                        if (this.unsafe) {
                            const decoded = jwt.verify(token, this.unsafe);
                            if (typeof decoded === 'string') throw new Err(400, null, 'Decoded JWT Should be Object');
                            req.token = {
                                access: decoded.access ? decoded.access : 'unknown'
                            };
                        } else {
                            throw err;
                        }
                    }
                } catch (err: any) {
                    return Err.respond(new Err(401, err, 'Invalid Token'), res);
                }
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
        }, (req: AuthRequest, res: Response) => {
            try {
                return res.json(req.auth);
            } catch (err) {
                Err.respond(err, res);
            }
        });

    }
}
