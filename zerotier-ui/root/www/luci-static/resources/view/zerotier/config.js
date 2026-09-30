/* SPDX-License-Identifier: GPL-3.0-only
 * Adapted from ImmortalWrt LuCI, Copyright (C) 2022 ImmortalWrt.org.
 * F50 adaptation targets the official OpenWrt ZeroTier 1.16.0 init schema.
 */
'use strict';
'require form';
'require view';
'require zerotier.common as common';
'require zerotier.runtime as runtime';

const CENTRAL_URL = 'https://my.zerotier.com/network';

function addFlag(section, definition) {
	const option = section.option(form.Flag, definition.name, definition.title, definition.description);
	option.default = definition.initial;
	option.rmempty = false;
	option.editable = true;
	return option;
}

function globalSection(map) {
	const section = map.section(form.NamedSection, 'global', 'zerotier', _('全局配置'));
	addFlag(section, { name: 'enabled', title: _('启用'), initial: '0' });
	const port = section.option(form.Value, 'port', _('监听端口'), _('留空使用 9993；0 表示随机端口。'));
	port.datatype = 'port';
	port.placeholder = '9993';
	port.rmempty = true;
	identityField(section);
	configurationPaths(section);
	addFlag(section, { name: 'fw_allow_input', title: _('允许入站流量'), initial: '0',
		description: _('允许外部流量与 ZeroTier 守护进程通信，用于建立虚拟网络连接。') });
	const central = section.option(form.Button, '_panel', _('ZeroTier 管理中心'),
		_('创建或管理您的 ZeroTier 网络，并授权客户端接入。'));
	central.inputtitle = _('打开网站');
	central.inputstyle = 'apply';
	central.onclick = function() { window.open(CENTRAL_URL, '_blank', 'noopener,noreferrer'); };
}

function identityField(section) {
	const option = section.option(form.Value, 'secret', _('客户端密钥'),
		_('留空保留当前身份；仅在需要迁移设备身份时填写新密钥。更换后可能需要重新授权。'));
	option.password = true;
	option.rmempty = true;
	option.cfgvalue = function(sectionId) {
		this.placeholder = this.map.data.get('zerotier', sectionId, 'secret') ? _('已配置，留空保留') : _('未配置，首次启动时生成');
		return '';
	};
	option.write = function(sectionId, value) {
		if (value !== '')
			this.map.data.set('zerotier', sectionId, 'secret', value);
	};
	// Empty fields must not erase the identity when another setting is saved.
	option.remove = function() {};
}

function configurationPaths(section) {
	const local = section.option(form.Value, 'local_conf_path', _('本地配置路径'),
		_('可选配置文件 local.conf 的路径（请参阅 <a href="https://docs.zerotier.com/config/#local-configuration-options" target="_blank" rel="noopener noreferrer">文档</a>）。'));
	local.placeholder = _('未指定');
	local.value('/etc/zerotier.conf');
	const directory = section.option(form.Value, 'config_path', _('配置路径'),
		_('持久配置目录，用于保留 controller、moon 等其他配置。'));
	directory.placeholder = _('未指定');
	directory.value('/etc/zerotier');
	addFlag(section, { name: 'copy_config_path', title: _('复制配置目录'), initial: '0',
		description: _('将持久配置目录的内容复制到内存中，以减少写入闪存；未指定目录时不生效。') });
}

function networkId(section) {
	const option = section.option(form.Value, 'id', _('网络 ID'), _('在 ZeroTier Central 中创建网络后填写其 16 位 ID，并授权本设备。'));
	option.rmempty = false;
	option.editable = true;
	option.validate = function(sectionId, value) {
		const otherIds = this.map.data.sections('zerotier', 'network')
			.filter(item => item['.name'] !== sectionId)
			.map(item => this.formvalue(item['.name']) ?? this.cfgvalue(item['.name']));
		return common.validateNetworkId(value, otherIds);
	};
}

function networkFlags(section) {
	addFlag(section, { name: 'allow_managed', title: _('允许管理 IP / 路由'), initial: '1',
		description: _('允许控制器设置私有或本地地址和路由。') });
	addFlag(section, { name: 'allow_global', title: _('允许公网 IP / 路由'), initial: '0',
		description: _('允许控制器设置公网范围的地址和路由。') });
	addFlag(section, { name: 'allow_default', title: _('允许默认路由'), initial: '0',
		description: _('允许控制器改变系统默认路由，可能影响当前连接。') });
	addFlag(section, { name: 'allow_dns', title: _('允许 DNS'), initial: '0',
		description: _('允许控制器设置 DNS 服务器。') });
	addFlag(section, { name: 'fw_allow_input', title: _('允许入站'), initial: '0',
		description: _('允许此 ZeroTier 网络访问本设备上的服务。') });
	addFlag(section, { name: 'fw_allow_forward', title: _('允许转发'), initial: '0',
		description: _('允许此 ZeroTier 网络与其他网络之间双向转发流量。') });
	addFlag(section, { name: 'fw_allow_masq', title: _('IP 动态伪装'), initial: '0',
		description: _('对发往此 ZeroTier 网络的流量启用源地址转换（NAT）。') });
}

function networkSection(map) {
	const section = map.section(form.GridSection, 'network', _('网络配置'),
		_('防火墙开关控制 ZeroTier 的附加规则；您已有的防火墙规则仍会生效。'));
	section.anonymous = false;
	section.addremove = true;
	section.sortable = true;
	section.rowcolors = true;
	section.nodescriptions = true;
	section.sectiontitle = function(sectionId) { return sectionId; };
	addFlag(section, { name: 'enabled', title: _('启用'), initial: '1' });
	networkId(section);
	networkFlags(section);
}

return view.extend({
	render: function() {
		const map = new form.Map('zerotier', _('ZeroTier'),
			_('ZeroTier 是一个开源、跨平台且易于使用的虚拟局域网 VPN。'));
		runtime.statusSection(map);
		globalSection(map);
		networkSection(map);
		return map.render();
	}
});
