'use strict';
'require view';

const DOONA_URL = 'http://192.168.77.1:9527/ui/';

return view.extend({
    render: function() {
        return E('div', { 'class': 'cbi-map' }, [
            E('h2', {}, 'Honk / Doona'),
            E('div', { 'class': 'cbi-map-descr' },
                '使用 Doona 管理 Honk 的节点、订阅和分流规则。'),
            E('p', {}, E('a', {
                'class': 'cbi-button cbi-button-action',
                'href': DOONA_URL,
                'target': '_blank',
                'rel': 'noopener noreferrer'
            }, '打开 Doona 管理界面')),
            E('p', {}, '在新页面中使用 Doona 管理员账号登录。')
        ]);
    },
    handleSave: null,
    handleSaveApply: null,
    handleReset: null
});
