'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

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

test('configuration fields use official defaults and integer port validation', () => {
    const sections = [];
    class Map {
        section(kind, ...args) {
            const section = { kind, args, options: [], option(type, name) {
                const option = { type, name };
                this.options.push(option);
                return option;
            } };
            sections.push(section);
            return section;
        }
        render() { return sections; }
    }
    const form = { Map, NamedSection: 'named', GridSection: 'grid', Flag: 'flag', Value: 'value' };
    const source = fs.readFileSync(path.join(root, 'www/luci-static/resources/view/zerotier/config.js'), 'utf8');
    const view = new Function('form', 'view', 'common', '_', source)(form, { extend: x => x }, common, x => x);
    view.render();
    assert.deepEqual(sections[0].args.slice(0, 2), ['global', 'zerotier']);
    assert.equal(sections[0].options.find(o => o.name === 'port').datatype, 'port');
    assert.deepEqual(sections[1].options.map(o => o.name), [
        'id', 'allow_managed', 'allow_global', 'allow_default', 'allow_dns'
    ]);
    const flags = sections.flatMap(s => s.options).filter(o => o.type === 'flag');
    flags.forEach(flag => {
        assert.equal(flag.rmempty, false);
        assert.equal(flag.default, flag.name === 'allow_managed' ? '1' : '0');
    });
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
