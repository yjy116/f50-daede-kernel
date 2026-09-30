/* SPDX-License-Identifier: GPL-3.0-only */
'use strict';
'require baseclass';
'require dom';
'require form';
'require fs';
'require poll';
'require rpc';
'require zerotier.common as common';

const POLL_SECONDS = 5;
const CLI = '/usr/bin/zerotier-cli';
const callServiceList = rpc.declare({ object: 'service', method: 'list', params: ['name'], expect: { '': {} } });

async function readRunning() {
	return common.serviceRunning(await callServiceList('zerotier'));
}

async function readAll() {
	const running = await readRunning();
	if (!running)
		return { running: false };
	const results = await Promise.all([fs.exec(CLI, ['-j', 'info']), fs.exec(CLI, ['-j', 'listnetworks'])]);
	return { running: true, info: common.parseInfo(results[0]), networks: common.parseNetworks(results[1]) };
}

async function statusResult() {
	try {
		return { data: await readAll() };
	}
	catch (error) {
		return { error };
	}
}

function serviceLabel(running) {
	return E('em', {}, E('strong', { style: 'color:' + (running ? 'green' : '#b42318') },
		running ? _('ZeroTier 运行中') : _('ZeroTier 未运行')));
}

function statusSection(map) {
	const section = map.section(form.TypedSection);
	section.anonymous = true;
	section.render = async function() {
		const content = E('p', {}, _('正在读取状态…'));
		const refresh = async function() {
			try {
				dom.content(content, serviceLabel(await readRunning()));
			}
			catch (error) {
				dom.content(content, E('strong', { class: 'text-danger' }, _('状态读取失败：') + error.message));
			}
		};
		await refresh();
		poll.add(refresh, POLL_SECONDS);
		return E('div', { class: 'cbi-section', role: 'status', 'aria-live': 'polite' }, [content]);
	};
	return section;
}

return baseclass.extend({ readAll, statusResult, statusSection });
