const {randomBytes} = require('node:crypto');
const {setTimeout: delay} = require('node:timers/promises');

const epochNanos = () => BigInt(Date.now()) * 1000000n;
const stringAttribute = (key, stringValue) => ({key, value: {stringValue}});
const integerAttribute = (key, value) => ({key, value: {intValue: String(value)}});

function traceSpan(traceId, spanId, kind, start, status, attributes, events = [], parentSpanId) {
    return {
        traceId, spanId, parentSpanId, kind, startTimeUnixNano: String(start), endTimeUnixNano: String(epochNanos()),
        status: {code: status >= 400 ? 2 : 1},
        attributes: [...attributes, integerAttribute('http.response.status_code', status)],
        events
    };
}

async function report(context, spans) {
    const collector = process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT;
    if (!collector) {
        return;
    }
    try {
        const response = await fetch(collector, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({resourceSpans: [{scopeSpans: [{scope: {name: 'ocean.fixture'}, spans}]}]}),
            signal: AbortSignal.timeout(5500)
        });
        if (!response.ok) {
            context.log.warn('ocean fixture trace export returned', response.status);
        }
    } catch {
        context.log.warn('ocean fixture trace export unavailable');
    }
}

module.exports = async function (context, request) {
    const start = epochNanos();
    const trace = randomBytes(16).toString('hex');
    const invocation = randomBytes(8).toString('hex');
    const spans = [];
    const events = [];
    const mode = request.query.mode;
    const setting = process.env.OCEAN_SETTING || 'unset';
    let status = 200;
    let payload = `node:${setting}\n`;
    const headers = {'Content-Type': 'text/plain; charset=utf-8'};
    context.log('ocean Node.js fixture invoked');
    try {
        if (mode === 'error') {
            await delay(35);
            status = 503;
            payload = 'node:fixture-error\n';
        } else if (mode === 'exception') {
            await delay(65);
            throw new RangeError('fixture message excluded from stored telemetry');
        } else if (mode === 'dependency') {
            const begin = epochNanos();
            const target = process.env.OCEAN_DEPENDENCY_URL || 'http://127.0.0.1:10000/';
            const response = await fetch(target, {signal: AbortSignal.timeout(2000)});
            await response.arrayBuffer();
            headers['x-ocean-fixture-dependency-status'] = String(response.status);
            spans.push(traceSpan(trace, randomBytes(8).toString('hex'), 3, begin, response.status,
                [stringAttribute('server.address', new URL(target).hostname)], [], invocation));
        }
    } catch (error) {
        const at = epochNanos();
        events.push({name: 'exception', timeUnixNano: String(at), attributes: [
            stringAttribute('exception.type', error.name), stringAttribute('exception.message', error.message)
        ]});
        status = 500;
        payload = 'node:fixture-exception\n';
    }
    headers['x-ocean-fixture-duration-ms'] = String(Number(epochNanos() - start) / 1000000);
    spans.push(traceSpan(trace, invocation, 2, start, status,
        [stringAttribute('http.route', '/api/hello'), stringAttribute('url.full', request.url)], events));
    await report(context, spans);
    context.res = {status, headers, body: payload};
};
