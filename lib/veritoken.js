"use strict";

module.exports = veritoken;

function veritoken(options, resolver) {
    if (typeof options === 'function') {
        resolver = options;
        options = undefined;
    }
    options = options || {};

    if (!resolver) throw new Error('veritoken() middleware requires a resolver');

    var property = options.property || options.attr;
    if (!property) throw  new Error('veritoken() middleware requires a options.property');

    return function (req, res, next) {
        if (req[property] !== undefined) return next();
        var token = tokenIdForRequest(req, options);
        if (!token) return next();
        resolver(token, function (err, result) {
            req[property] = result || null;
            next(err);
        });
    }
}

function tokenIdForRequest(req, options) {
    var params = options.params || [];
    var headers = options.headers || [];
    var cookies = options.cookies || [];
    var i = 0;
    var length;
    var id;

    for (length = params.length; i < length; i++) {
        id = req.param(params[i]);

        if (typeof id === 'string') {
            return id;
        }
    }

    for (i = 0, length = headers.length; i < length; i++) {
        id = req.header(headers[i]);

        if (typeof id === 'string') {
            // Add support for oAuth 2.0 bearer token
            // http://tools.ietf.org/html/rfc6750
            if (id.indexOf('Bearer ') === 0) {
                id = id.substring(7);
                // Decode from base64
                var buf = new Buffer(id, 'base64');
                id = buf.toString('utf8');
            }
            return id;
        }
    }

    if (req.signedCookies) {
        for (i = 0, length = cookies.length; i < length; i++) {
            id = req.signedCookies[cookies[i]];

            if (typeof id === 'string') {
                return id;
            }
        }
    }
    return null;
}