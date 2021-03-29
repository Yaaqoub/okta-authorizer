const axios = require('axios');
const fs = require('fs');
const qs = require('qs');
const OktaJwtVerifier = require('@okta/jwt-verifier');

const oktaJwtVerifier = new OktaJwtVerifier({
    issuer: process.env.ISSUER
});

module.exports.public = async event => {
    return {
        statusCode: 200,
        body: JSON.stringify(
            {
                message: 'Awesome Travel Inc can take you anywhere',
            },
            null,
            2
            )
    }
}

module.exports.authenticated = async event => {
    return {
        statusCode: 200,
        body: JSON.stringify(
            {
                message: 'Welcome registered user, where do you want to go today?',
            },
            null,
            2
            )
    }
}

module.exports.bookings = async event => {
    return {
        statusCode: 200,
        body: JSON.stringify(
            {
                message: 'Here are your bookings.',
                tickets: [
                    {id:123, from:"LHR", to: "SFO", seatPref: "window" },
                    {id:456, from: "AMS", to: "LAS", seatPref: "aisle", upgrade: "yes" }
                ]
            },
            null,
            2
            )
    }
}

module.exports.sensitive = async event => {
    return {
        statusCode: 200,
        body: JSON.stringify(
            {
                message: 'Here is your profile',
                profile: {
                    title: "Mr",
                    givenName: "Dade",
                    familyName: "Murphy",
                    passportNumber: "533301334",
                    nationality: "American"
                }
            },
            null,
            2
            )
    }
}

module.exports.callback = async event => {
    let accessToken, message, user;
    let statusCode = 200;

    try {
        if (event.queryStringParameters && event.queryStringParameters.code) {
            const data = qs.stringify({
                grant_type: 'authorization_code',
                redirect_uri: process.env.APP_REDIRECT_URI,
                code: event.queryStringParameters.code
            });

            const tokenResponse = await axios({
                method: 'post',
                url: `${process.env.ISSUER}/v1/token`,
                auth: {
                    username: process.env.OKTA_CLIENT_ID,
                    password: process.env.OKTA_CLIENT_SECRET
                },
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                data: data
            });

            accessToken = tokenResponse.data.access_token;

            let tokenData = await oktaJwtVerifier.verifyAccessToken(accessToken, process.env.AUDIENCE);
            user = {
                email: tokenData.claims.sub
            }
            message = 'Authentication is successful.';
        } else {
            message = 'Authorization code is not provided.';
            statusCode = 401;
        }
    } catch (err) {
        message = 'Something wrong! Contact your Okta admin.';
        statusCode = 403;
    }

    return {
        statusCode: statusCode,
        body: JSON.stringify(
            {
                message: message,
                accessToken,
                user
            },
            null,
            2
        )
    }
}
