/**
 * Authentication Middleware
 * @class
 *
 */
export default class AuthenticationMiddleware {
    constructor(opts) {
        this.opts = opts;
    }

    auth() {
        return async (req, res, next) => {
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
        }
    }
}
