const OktaJwtVerifier = require('@okta/jwt-verifier');
const axios = require('axios');
const qs = require('qs');

const oktaJwtVerifier = new OktaJwtVerifier({
    issuer: process.env.ISSUER
});

exports.auth = function (event, context) {
    // TASK 1
    let bearer = event.authorizationToken;

    if (bearer) {
        oktaJwtVerifier.verifyAccessToken(getToken(bearer), process.env.AUDIENCE)
            .then((response) => {
                context.succeed(generateAuthResponse(response.claims.sub, 'Allow',  event.methodArn));
            })
            .catch(() => {
                context.fail('Unauthorized');
            });
    } else {
        context.fail('Unauthorized');
    }
}

exports.bookings = function (event, context) {
    // TASK 2
    let bearer = event.authorizationToken;

    if (bearer) {
        oktaJwtVerifier.verifyAccessToken(getToken(bearer), process.env.AUDIENCE)
            .then((response) => {
                if (response.claims.scp.includes('bookings:read')) {
                    context.succeed(generateAuthResponse(response.claims.sub, 'Allow',  event.methodArn));
                } else {
                    context.succeed(generateAuthResponse(response.claims.sub, 'Deny',  event.methodArn));
                }
            })
            .catch(() => {
                context.fail('Unauthorized');
            });
    } else {
        context.fail('Unauthorized');
    }
}

exports.sensitive = function (event, context) {
    // TASK 3
    let bearer = event.authorizationToken;

    if (bearer) {
        const data = qs.stringify({
            'token': getToken(bearer),
            'token_type_hint': 'access_token'
        });

        axios({
            method: 'POST',
            url: `${process.env.ISSUER}/v1/introspect`,
            auth: {
                username: process.env.OKTA_CLIENT_ID,
                password: process.env.OKTA_CLIENT_SECRET
            },
            headers: {
                accept: 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            data: data
        })
            .then((response) => {
                if (response.data.active) {
                    context.succeed(generateAuthResponse(response.data.sub, 'Allow',  event.methodArn));
                } else {
                    context.fail('Unauthorized');
                }
            })
            .catch(() => {
                context.fail('Unauthorized');
            });
    } else {
        context.fail('Unauthorized');
    }
}

function generateAuthResponse(principalId, effect, methodArn) {
    return {
        'principalId': principalId,
        'policyDocument': {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: effect,
                Resource: methodArn
            }]
        }
    }
}

function getToken(bearerToken) {
    let parted = bearerToken.split(' ');
    if (parted.length === 2) {
        return parted[1];
    } else {
        return null;
    }
}
