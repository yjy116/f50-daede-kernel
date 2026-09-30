'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { configurationHarness } = require('./test_ui_helpers.cjs');

const root = path.join(__dirname, 'root');
const commonPath = path.join(root, 'www/luci-static/resources/zerotier/common.js');
const common = new Function('baseclass', fs.readFileSync(commonPath, 'utf8'))({ extend: x => x });

test('network ID validation accepts exact hex IDs and rejects invalid or duplicate IDs', () => {
    assert.equal(common.validateNetworkId('1234567890abcdef', []), true);
    assert.equal(common.validateNetworkId('ABCDEF1234567890', []), true);
    assert.notEqual(common.validateNetworkId('../invalid/path!', []), true);
    assert.notEqual(common.validateNetworkId('1234', []), true);
    assert.notEqual(common.validateNetworkId('ABCDEF1234567890', ['abcdef1234567890']), true);
});

test('service status detects any running instance and exposes malformed RPC data', () => {
    assert.equal(common.serviceRunning({}), false);
    assert.equal(common.serviceRunning({ zerotier: { instances: {} } }), false);
    assert.equal(common.serviceRunning({ zerotier: { instances: { alternate: { running: true } } } }), true);
    assert.throws(() => common.serviceRunning(null), /服务/);
    assert.throws(() => common.serviceRunning({ zerotier: { instances: [] } }), /服务/);
    assert.throws(() => common.serviceRunning({ zerotier: { instances: { bad: { running: 'false' } } } }), /服务/);
});

test('new firewall controls default off while existing networks remain enabled', async () => {
    const { sections, view } = configurationHarness();
    await view.render();
    const global = sections.find(s => s.kind === 'named');
    const networks = sections.find(s => s.kind === 'grid');
    assert.deepEqual(global.args.slice(0, 2), ['global', 'zerotier']);
    assert.equal(global.options.find(o => o.name === 'port').datatype, 'port');
    assert.equal(networks.anonymous, false);
    assert.equal(networks.options.find(o => o.name === 'enabled')?.default, '1');
    assert.equal(networks.options.find(o => o.name === 'allow_managed').default, '1');
    const firewallFlags = sections.flatMap(s => s.options).filter(o => o.name.startsWith('fw_'));
    assert.equal(firewallFlags.length, 4);
    firewallFlags.forEach(flag => {
        assert.equal(flag.default, '0');
        assert.equal(flag.rmempty, false);
    });
    assert.equal(global.options.find(o => o.name === 'copy_config_path')?.default, '0');
});

test('configuration styling is enclosed in its own view and loads only its stylesheet', async () => {
    const { view } = configurationHarness();
    const rendered = await view.render();
    assert.equal(rendered.attributes.class, 'zerotier-view');
    assert.equal(rendered.children[0].tag, 'link');
    assert.equal(rendered.children[0].attributes.href, '/luci-static/resources/zerotier/appearance.css');
    assert.equal(rendered.children[1].tag, 'div');
});

test('render and an empty secret edit preserve the existing identity without exposing it', async () => {
    const currentIdentity = 'sensitive-test-identity';
    const writes = [];
    const data = { get: () => currentIdentity, set: (...args) => writes.push(args),
        unset: () => { throw new Error('Identity must not be removed by an empty edit'); } };
    const { sections, view } = configurationHarness(data);
    const rendered = await view.render();
    const secret = sections.find(s => s.kind === 'named').options.find(o => o.name === 'secret');
    assert.ok(secret, 'A masked identity replacement field is required');
    assert.equal(secret.password, true);
    assert.equal(secret.cfgvalue('global'), '');
    secret.write('global', '');
    secret.remove('global');
    assert.deepEqual(writes, []);
    assert.equal(JSON.stringify(rendered).includes(currentIdentity), false);
    secret.write('global', 'replacement-test-identity');
    assert.deepEqual(writes, [['zerotier', 'global', 'secret', 'replacement-test-identity']]);
});

test('network duplicate validation includes both existing anonymous and named rows', async () => {
    const data = { sections: () => [{ '.name': 'cfg012345' }, { '.name': 'travel' }] };
    const { sections, view } = configurationHarness(data);
    await view.render();
    const network = sections.find(s => s.kind === 'grid');
    const id = network.options.find(o => o.name === 'id');
    id.formvalue = section => section === 'travel' ? 'abcdef1234567890' : undefined;
    id.cfgvalue = section => section === 'cfg012345' ? '1234567890abcdef' : undefined;
    assert.equal(id.validate('cfg012345', '1234567890abcdef'), true);
    assert.notEqual(id.validate('cfg012345', 'ABCDEF1234567890'), true);
    assert.notEqual(id.validate('travel', '1234567890abcdef'), true);
});

test('CLI failures, bad JSON and wrong schema remain visible', () => {
    assert.throws(() => common.parseInfo({ code: 1, stderr: 'connection refused' }), /connection refused/);
    assert.throws(() => common.parseInfo({ code: 0, stdout: 'not json' }), /JSON/);
    assert.throws(() => common.parseInfo({ code: 0, stdout: '{}' }), /节点/);
    assert.throws(() => common.parseNetworks({ code: 0, stdout: '{}' }), /网络/);
    assert.throws(() => common.parseNetworks({ code: 0, stdout: '[{"id":"bad"}]' }), /网络/);
});

test('public status projection omits unrelated fields and does not infer authorization', () => {
    const info = { address: '1234567890', version: '1.16.0', online: true, unrelated: 'excluded' };
    assert.deepEqual(common.parseInfo({ code: 0, stdout: JSON.stringify(info) }), {
        address: '1234567890', version: '1.16.0', online: true
    });
    const network = { id: '1234567890abcdef', name: '', status: 'ACCESS_DENIED',
        assignedAddresses: [], portDeviceName: 'zt12345678', unrelated: 'excluded' };
    const rows = common.parseNetworks({ code: 0, stdout: JSON.stringify([network]) });
    assert.equal(rows[0].status, 'ACCESS_DENIED');
    assert.equal(rows[0].unrelated, undefined);
    assert.equal(common.networkStatus('ACCESS_DENIED'), '未获授权');
    assert.equal(common.networkStatus('FUTURE_STATUS'), 'FUTURE_STATUS');
});

test('ACL grants only exact read-only CLI commands and configuration access', () => {
    const acl = JSON.parse(fs.readFileSync(path.join(root, 'usr/share/rpcd/acl.d/luci-app-zerotier.json')));
    const permission = acl['luci-app-zerotier'];
    assert.deepEqual(Object.keys(permission.read.file).sort(), [
        '/usr/bin/zerotier-cli -j info', '/usr/bin/zerotier-cli -j listnetworks'
    ]);
    assert.deepEqual(permission.write, { uci: ['zerotier'] });
    assert.equal(JSON.stringify(acl).includes('identity.secret'), false);
});

test('menu defines VPN entry and no install-time configuration mutation', () => {
    const menu = JSON.parse(fs.readFileSync(path.join(root, 'usr/share/luci/menu.d/luci-app-zerotier.json')));
    assert.equal(menu['admin/vpn'].title, 'VPN');
    assert.equal(menu['admin/vpn/zerotier/config'].action.path, 'zerotier/config');
    assert.equal(menu['admin/vpn/zerotier/status'].action.path, 'zerotier/status');
    assert.equal(fs.existsSync(path.join(root, 'etc/uci-defaults')), false);
    assert.equal(fs.existsSync(path.join(root, 'etc/config/zerotier')), false);
});
