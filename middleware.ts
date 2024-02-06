import Err from '@openaddresses/batch-error';
import jwt from 'jsonwebtoken';
import { CookieJar, Cookie } from 'tough-cookie';
import { CookieAgent } from 'http-cookie-agent/undici';
import { Request, Response, NextFunction } from 'express';
import EventEmitter from 'events';

export interface ConfigOpts {
    secret: string;
    unsafe?: string;
    api: string;
    group?: string;
}

export enum AuthUserAccess {
    ADMIN = 'admin',
    USER = 'user'
}

function castUserAccessEnum(str: string): AuthUserAccess | undefined {
  const value = AuthUserAccess[str.toUpperCase() as keyof typeof AuthUserAccess];
  return value;
}

export enum AuthResourceAccess {
    DATA = 'data',
    LAYER = 'layer',
    IMPORT = 'import',
    CONNECTION = 'connection'
}

function castResourceAccessEnum(str: string): AuthResourceAccess | undefined {
  const value = AuthResourceAccess[str.toUpperCase() as keyof typeof AuthResourceAccess];
  return value;
}

export interface AuthRequest extends Request {
    token?: AuthResource | AuthUser;
    auth?: AuthResource | AuthUser;
}

/**
 * These will be looked up in the database to ensure they are still active
 */
export class AuthResource {
    id: number | string;
    access: AuthResourceAccess;
    token: string;
    internal: boolean;

    constructor(
        token: string,
        access: AuthResourceAccess,
        id: number | string,
        internal: boolean
    ) {
        this.token = token;
        this.internal = internal;
        this.access = access;
        this.id = id;
    }
}

/**
 * These tokens are ephemeral JWTs
 */
export class AuthUser {
    access: AuthUserAccess;
    email: string;

    constructor(access: AuthUserAccess, email: string) {
        this.access = access;
        this.email = email;
    }

    is_user() {
        return this.email && this.email.length;
    }
}

export function tokenParser(token: string, secret: string): AuthUser | AuthResource {
    if (token.startsWith('etl.')) {
        token = token.replace(/^etl\./, '');
        const decoded = jwt.verify(token, secret);
        if (typeof decoded === 'string') throw new Err(400, null, 'Decoded JWT Should be Object');
        if (!decoded.access || typeof decoded.access !== 'string') throw new Err(401, null, 'Invalid Token');
        if (!decoded.internal || typeof decoded.internal !== 'boolean') decoded.internal = false;
        if (!decoded.id) throw new Err(401, null, 'Invalid Token');
        const access = castResourceAccessEnum(decoded.access);
        if (!access) throw new Err(400, null, 'Invalid Resource Access Value');
        return new AuthResource(`etl.${token}`, access, decoded.id, decoded.internal);
    } else {
        const decoded = jwt.verify(token, secret);
        if (typeof decoded === 'string') throw new Err(400, null, 'Decoded JWT Should be Object');
        if (!decoded.email || typeof decoded.email !== 'string') throw new Err(401, null, 'Invalid Token');
        if (!decoded.access || typeof decoded.access !== 'string') throw new Err(401, null, 'Invalid Token');

        const access = castUserAccessEnum(decoded.access);
        if (!access) throw new Err(400, null, 'Invalid User Access Value');

        const auth: {
            access: AuthUserAccess;
            email: string;
        } = {
            email: decoded.email,
            access
        };

        return new AuthUser(auth.access, auth.email);
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
export default class AuthenticationMiddleware extends EventEmitter {
    name: string;
    secret: string;
    unsafe: string | null;
    api: string;
    group?: string | null;

    constructor(opts: ConfigOpts) {
        super();
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
                    username: { type: 'string' },
                    password: { type: 'string' }
                }
            },
            res: {
                type: 'object',
                required: ['token'],
                properties: {
                    token: { type: 'string' },
                    access: { type: 'string' },
                    email: { type: 'string' }
                }
            }
        }, async (req: Request, res: Response) => {
            try {
                const url = new URL('/oauth/token', this.api);
                url.searchParams.append('grant_type', 'password');
                url.searchParams.append('username', req.body.username);
                url.searchParams.append('password', req.body.password);

                const authres = await fetch(url, {
                    method: 'POST'
                });

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
                        // @ts-expect-error
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

                this.emit('login', req.body);

                const split = Buffer.from(body.access_token, 'base64').toString().split('}').map((ext) => { return ext + '}'});
                if (split.length < 2) throw new Err(500, null, 'Unexpected TAK JWT Format');
                const contents: { sub: string; aud: string; nbf: number; exp: number; iat: number; } = JSON.parse(split[1]);

                return res.json({
                    access: 'user',
                    email: contents.sub,
                    token: jwt.sign({ access: 'user', email: contents.sub }, this.secret)
                });
            } catch (err) {
                Err.respond(err, res);
            }
        });

        router.router.use((req: AuthRequest, res: Response, next: NextFunction) => {
            if (req.header && req.header('authorization')) {
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
                        req.auth = tokenParser(authorization[1], this.secret);
                    } catch (err) {
                        if (this.unsafe) {
                            req.auth = tokenParser(authorization[1], this.unsafe);
                        } else {
                            throw err;
                        }
                    }
                } catch (err: any) {
                    if (err instanceof Err) return Err.respond(err, res);
                    return Err.respond(new Err(401, err, 'Invalid Token'), res);
                }
            } else if (req.query && req.query.token && typeof req.query.token === 'string') {
                const token = req.query.token;

                try {
                    try {
                        req.token = tokenParser(token, this.secret);
                    } catch (err) {
                        if (this.unsafe) {
                            req.token = tokenParser(token, this.unsafe);
                        } else {
                            throw err;
                        }
                    }
                } catch (err: any) {
                    if (err instanceof Err) return Err.respond(err, res);
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
