const version = require('./package-version.js');

module.exports = async function (context) {
    const sticky = process.env.OCEAN_STICKY ? `:${process.env.OCEAN_STICKY}` : '';
    context.res = {
        status: 200,
        headers: {'Content-Type': 'text/plain; charset=utf-8'},
        body: `zip:${version}:${process.env.OCEAN_SETTING || 'unset'}${sticky}\n`
    };
};
