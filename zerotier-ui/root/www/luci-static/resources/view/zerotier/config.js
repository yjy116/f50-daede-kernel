/* SPDX-License-Identifier: GPL-3.0-only
 * Adapted from ImmortalWrt LuCI, Copyright (C) 2022 ImmortalWrt.org.
 * F50 adaptation targets the official OpenWrt ZeroTier 1.16.0 init schema.
 */
'use strict';
'require form';
'require view';
'require zerotier.common as common';

function addFlag(section, definition) {
	const option = section.option(form.Flag, definition.name, definition.title, definition.description);
	option.default = definition.initial;
	option.rmempty = false;
	option.editable = true;
	return option;
}

function globalSection(map) {
	const section = map.section(form.NamedSection, 'global', 'zerotier', _('全局设置'));
	addFlag(section, { name: 'enabled', title: _('启用 ZeroTier'), initial: '0',
		description: _('保存并应用后按此设置启动或停止服务；添加的每个网络都会尝试加入。') });
	const port = section.option(form.Value, 'port', _('监听端口'), _('留空使用 9993；0 表示随机端口。'));
	port.datatype = 'port';
	port.placeholder = '9993';
	port.rmempty = true;
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
}

function networkSection(map) {
	const section = map.section(form.GridSection, 'network', _('网络配置'),
		_('官方后端会加入列表中的所有网络。如曾自定义持久配置目录，删除表项不会清理该目录内的旧网络文件。防火墙规则请在“网络 → 防火墙”中单独设置。'));
	section.anonymous = true;
	section.addremove = true;
	section.sortable = true;
	section.nodescriptions = false;
	networkId(section);
	networkFlags(section);
}

return view.extend({
	render: function() {
		const map = new form.Map('zerotier', _('ZeroTier'),
			_('F50 官方 ZeroTier 后端配置。仅修改本页可见选项；节点私钥不会在此显示。保存并应用会重载服务，现有 ZeroTier 连接可能短暂中断。'));
		globalSection(map);
		networkSection(map);
		return map.render();
	}
});
