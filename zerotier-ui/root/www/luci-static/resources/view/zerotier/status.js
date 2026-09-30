/* SPDX-License-Identifier: GPL-3.0-only
 * Status view for the official OpenWrt ZeroTier backend.
 */
'use strict';
'require dom';
'require poll';
'require ui';
'require view';
'require zerotier.common as common';
'require zerotier.runtime as runtime';

const POLL_SECONDS = 5;

function statusRow(label, value) {
	return E('tr', { class: 'tr' }, [E('td', { class: 'td' }, label), E('td', { class: 'td' }, value)]);
}

function nodeTable(data) {
	return E('table', { class: 'table' }, [
		statusRow(_('服务'), _('运行中')),
		statusRow(_('控制平面'), data.info.online ? _('在线') : _('离线')),
		statusRow(_('公开节点 ID'), data.info.address),
		statusRow(_('客户端版本'), data.info.version)
	]);
}

function networkTable(networks) {
	if (networks.length === 0)
		return E('p', {}, _('当前没有加入的网络。请在配置页填写自己的网络 ID，保存并应用。'));
	const table = E('table', { class: 'table' }, [E('tr', { class: 'tr' },
		[_('网络 ID'), _('名称'), _('状态'), _('接口'), _('分配地址')].map(label => E('th', { class: 'th' }, label)))]);
	networks.forEach(network => table.appendChild(E('tr', { class: 'tr' }, [
		network.id, network.name || '—', common.networkStatus(network.status),
		network.device || '—', network.addresses.join(', ') || '—'
	].map(value => E('td', { class: 'td' }, value)))));
	return table;
}

function renderResult(result) {
	if (result.error)
		return E('div', { class: 'alert-message warning' }, [_('状态读取失败：'), result.error.message]);
	if (!result.data.running)
		return E('p', {}, _('服务未运行。请在配置页启用 ZeroTier 并保存应用。'));
	return E('div', {}, [nodeTable(result.data), E('h3', {}, _('网络状态')), networkTable(result.data.networks)]);
}

return view.extend({
	load: runtime.statusResult,
	render: function(result) {
		const content = E('div', {}, renderResult(result));
		const refresh = async function() { dom.content(content, renderResult(await runtime.statusResult())); };
		poll.add(refresh, POLL_SECONDS);
		return E('div', { class: 'cbi-map' }, [
			E('h2', {}, _('ZeroTier 接口信息')),
			E('p', { class: 'cbi-map-descr' }, _('服务运行不等于网络已授权。此页只读取状态，不加入或退出网络；每 5 秒刷新一次。')),
			E('button', { class: 'btn cbi-button', click: ui.createHandlerFn(this, refresh) }, _('刷新状态')),
			content
		]);
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
