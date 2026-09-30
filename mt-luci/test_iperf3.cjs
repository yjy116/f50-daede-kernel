'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const source = fs.readFileSync(path.join(__dirname,
    'vendor/luci-app-iperf3/htdocs/luci-static/resources/view/iperf3/index.js'), 'utf8');

function harness(options = {}) {
    const calls = [], notices = [], nodes = [];
    const values = { server: '198.51.100.4', port: '5201', reverse: '0', ...options.values };
    const execute = (command, args) => {
        calls.push({ command, args });
        if (options.failure) return Promise.reject(new Error(options.failure));
        return Promise.resolve(options.result || { code: 0, stdout: 'real command result', stderr: '' });
    };
    const element = (...args) => ({ args, appendChild: node => nodes.push(node),
        removeChild: () => {}, lastChild: {}, });
    const ui = { showModal: (...args) => { nodes.push(args); return element(); },
        hideModal: () => {}, addNotification: (...args) => notices.push(args) };
    const view = new Function('view', 'form', 'fs', 'ui', 'uci', 'E', '_', source)(
        { extend: value => value }, {}, { exec: execute, exec_direct: execute }, ui,
        { get_first: (_config, _type, key) => values[key] }, element, value => value);
    return { view, calls, notices, nodes };
}

test('client disabled reverse sends neither -R nor an empty argument', async () => {
    const h = harness();
    await h.view.handleStartTest();
    assert.deepEqual(h.calls, [{ command: '/usr/bin/iperf3',
        args: ['-c', '198.51.100.4', '-p', '5201'] }]);
});

test('enabled reverse adds exactly one -R', async () => {
    const h = harness({ values: { reverse: '1' } });
    await h.view.handleStartTest();
    assert.deepEqual(h.calls[0].args, ['-c', '198.51.100.4', '-p', '5201', '-R']);
});

test('absent reverse does not pass an empty argument', async () => {
    const h = harness({ values: { reverse: undefined } });
    await h.view.handleStartTest();
    assert.equal(h.calls[0].args.includes(''), false);
});

test('server nonzero exit reports stderr and never reports success', async () => {
    const h = harness({ result: { code: 1, stdout: '', stderr: 'Address already in use' } });
    await h.view.handleStartServer();
    const text = JSON.stringify(h.notices);
    assert.match(text, /Address already in use/);
    assert.doesNotMatch(text, /started successfully/);
});

test('client nonzero exit shows actual stderr', async () => {
    const h = harness({ result: { code: 1, stdout: '', stderr: 'Connection refused' } });
    await h.view.handleStartTest();
    assert.match(JSON.stringify([h.notices, h.nodes]), /Connection refused/);
});

test('stop uses an absolute allowed command and checks nonzero exit', async () => {
    const h = harness({ result: { code: 1, stdout: '', stderr: 'no process killed' } });
    await h.view.handleStopServer();
    assert.deepEqual(h.calls[0], { command: '/usr/bin/killall', args: ['iperf3'] });
    assert.match(JSON.stringify(h.notices), /no process killed/);
    assert.doesNotMatch(JSON.stringify(h.notices), /stopped successfully/);
});

test('RPC failures are surfaced without a success message', async () => {
    const h = harness({ failure: 'Permission denied' });
    await h.view.handleStartServer();
    await Promise.resolve();
    assert.match(JSON.stringify(h.notices), /Permission denied/);
    assert.doesNotMatch(JSON.stringify(h.notices), /successfully/);
});
