/* SPDX-License-Identifier: GPL-3.0-only */
'use strict';
'require baseclass';

const NETWORK_ID = /^[0-9a-f]{16}$/i;
const NODE_ID = /^[0-9a-f]{10}$/i;

function isObject(value) {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseJson(result) {
	if (!isObject(result) || result.code !== 0)
		throw new Error('ZeroTier 命令失败：' + (result && (result.stderr || result.stdout) || '未返回退出状态'));
	try {
		return JSON.parse(result.stdout);
	}
	catch (error) {
		throw new Error('ZeroTier 返回了无效 JSON：' + error.message);
	}
}

function validateNetworkId(value, otherIds) {
	if (!NETWORK_ID.test(value))
		return '网络 ID 必须是 16 位十六进制字符。';
	if (otherIds.some(id => typeof id === 'string' && id.toLowerCase() === value.toLowerCase()))
		return '此网络 ID 已存在，请勿重复添加。';
	return true;
}

function serviceRunning(result) {
	if (!isObject(result))
		throw new Error('服务查询返回了无效数据。');
	if (!Object.hasOwn(result, 'zerotier'))
		return false;
	const service = result.zerotier;
	if (!isObject(service) || (service.instances !== undefined && !isObject(service.instances)))
		throw new Error('ZeroTier 服务实例数据无效。');
	const instances = Object.values(service.instances || {});
	if (instances.some(instance => !isObject(instance) || typeof instance.running !== 'boolean'))
		throw new Error('ZeroTier 服务运行标记无效。');
	return instances.some(instance => instance.running === true);
}

function parseInfo(result) {
	const info = parseJson(result);
	if (!isObject(info) || !NODE_ID.test(info.address) || typeof info.version !== 'string' ||
		typeof info.online !== 'boolean')
		throw new Error('ZeroTier 节点状态字段不完整。');
	return { address: info.address, version: info.version, online: info.online };
}

function parseNetwork(network) {
	if (!isObject(network) || !NETWORK_ID.test(network.id) || typeof network.name !== 'string' ||
		typeof network.status !== 'string' || typeof network.portDeviceName !== 'string' ||
		!Array.isArray(network.assignedAddresses) || network.assignedAddresses.some(ip => typeof ip !== 'string'))
		throw new Error('ZeroTier 网络状态字段不完整。');
	return { id: network.id, name: network.name, status: network.status,
		device: network.portDeviceName, addresses: network.assignedAddresses.slice() };
}

function parseNetworks(result) {
	const networks = parseJson(result);
	if (!Array.isArray(networks))
		throw new Error('ZeroTier 网络列表不是数组。');
	return networks.map(parseNetwork);
}

function networkStatus(status) {
	const labels = { OK: '已加入', ACCESS_DENIED: '未获授权', NOT_FOUND: '网络不存在',
		REQUESTING_CONFIGURATION: '正在获取配置', PORT_ERROR: '虚拟接口错误',
		CLIENT_TOO_OLD: '客户端版本过旧', AUTHENTICATION_REQUIRED: '需要身份认证' };
	return labels[status] || status;
}

return baseclass.extend({ validateNetworkId, serviceRunning, parseInfo, parseNetworks, networkStatus });
