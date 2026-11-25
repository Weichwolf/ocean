module.exports = async function (context, request) {
    const fail = request.query.mode === 'error';
    const setting = process.env.OCEAN_SETTING || 'unset';
    context.log('ocean Node.js fixture invoked');
    context.res = {
        status: fail ? 503 : 200,
        headers: {'Content-Type': 'text/plain; charset=utf-8'},
        body: fail ? 'node:fixture-error\n' : `node:${setting}\n`
    };
};
