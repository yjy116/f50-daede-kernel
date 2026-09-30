/* SPDX-License-Identifier: GPL-3.0-only */
'use strict';
'require baseclass';

function wrap(content) {
	return E('div', { class: 'zerotier-view' }, [
		E('link', { rel: 'stylesheet', href: L.resource('zerotier/appearance.css') }),
		content
	]);
}

return baseclass.extend({ wrap });
