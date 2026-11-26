const version = require('./package-version.js');

module.exports = async function (context) {
    context.res = {
        status: 200,
        headers: {'Content-Type': 'text/plain; charset=utf-8'},
        body: `zip:${version}:${process.env.OCEAN_SETTING || 'unset'}\n`
    };
};
