'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadModule, element } = require('./test_ui_helpers.cjs');
const common = loadModule('zerotier/common.js', { baseclass: { extend: x => x } });

function runtimeHarness(serviceReplies, commandReply) {
    const calls = [];
    const polls = [];
    const rpc = { declare: () => async name => {
        assert.equal(name, 'zerotier');
        const reply = serviceReplies.shift();
        if (reply instanceof Error) throw reply;
        return reply;
    } };
    const runtime = loadModule('zerotier/runtime.js', {
        baseclass: { extend: x => x }, common, rpc, E: element, _: x => x,
        form: { TypedSection: 'typed' },
        dom: { content(node, value) { node.children = value; } },
        poll: { add(callback, interval) { polls.push({ callback, interval }); } },
        fs: { exec: async (command, args) => { calls.push([command, args]); return commandReply; } }
    });
    return { runtime, calls, polls };
}

test('stopped service status does not execute CLI commands or claim online', async () => {
    const { runtime, calls } = runtimeHarness([{}]);
    assert.deepEqual(await runtime.readAll(), { running: false });
    assert.deepEqual(calls, []);
});

test('running service CLI failure remains a status error instead of a stopped state', async () => {
    const service = { zerotier: { instances: { service: { running: true } } } };
    const { runtime, calls } = runtimeHarness([service], { code: 1, stderr: 'unreachable test API' });
    const result = await runtime.statusResult();
    assert.match(result.error.message, /unreachable test API/);
    assert.equal(result.data, undefined);
    assert.deepEqual(calls, [
        ['/usr/bin/zerotier-cli', ['-j', 'info']],
        ['/usr/bin/zerotier-cli', ['-j', 'listnetworks']]
    ]);
});

test('configuration status banner exposes RPC failures and recovers on the next poll', async () => {
    const service = { zerotier: { instances: { service: { running: true } } } };
    const { runtime, polls } = runtimeHarness([new Error('test permission denied'), service]);
    const section = {};
    runtime.statusSection({ section: () => section });
    const card = await section.render();
    assert.match(JSON.stringify(card), /状态读取失败.*test permission denied/);
    assert.equal(card.attributes.role, 'status');
    assert.equal(card.attributes['aria-live'], 'polite');
    assert.equal(polls.length, 1);
    await polls[0].callback();
    assert.match(JSON.stringify(card), /ZeroTier 运行中/);
    assert.doesNotMatch(JSON.stringify(card), /permission denied/);
});
