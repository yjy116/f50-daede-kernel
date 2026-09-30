'use strict';
'require view';
'require form';
'require fs';
'require ui';
'require uci';

const DEFAULT_PORT = '5201';

function checkedOutput(result) {
    if (!result || !Number.isInteger(result.code))
        throw new Error(_('Invalid command response'));
    if (result.code !== 0)
        throw new Error(result.stderr || result.stdout || _('Command failed') + ' (' + result.code + ')');
    return result.stdout || '';
}

function dismissButton() {
    return E('button', { 'class': 'btn', 'click': () => ui.hideModal() }, _('Dismiss'));
}

return view.extend({
    load: function() {
        return fs.exec_direct('/usr/bin/iperf3', ['--version']);
    },

    render: function() {
        const m = new form.Map('iperf3', _('iPerf3'), _('This is the iPerf3 configuration page.'));
        const s = m.section(form.TypedSection, 'iperf3', _('Settings'));
        s.anonymous = true;
        let o = s.option(form.Value, 'server', _('Server'), _('The iPerf3 server to connect to.'));
        o.datatype = 'host';
        o = s.option(form.Value, 'port', _('Port'), _('The port to use for the iPerf3 connection.'));
        o.datatype = 'port';
        o.placeholder = DEFAULT_PORT;
        o = s.option(form.Flag, 'reverse', _('Reverse'), _('Run in reverse mode.'));
        o.default = o.disabled;
        o = s.option(form.Button, '_start', _('Start Client Mode'));
        o.inputtitle = _('Start iPerf3 Client');
        o.onclick = () => m.save().then(() => this.handleStartTest());
        o = s.option(form.Button, '_start_server', _('Start Server Mode'));
        o.inputtitle = _('Start iPerf3 Server');
        o.onclick = () => m.save().then(() => this.handleStartServer());
        o = s.option(form.Button, '_stop_server', _('Stop iperf3'));
        o.inputtitle = _('Stop iPerf3 Server');
        o.onclick = () => this.handleStopServer();
        return m.render();
    },

    handleStartTest: function() {
        const server = uci.get_first('iperf3', 'iperf3', 'server');
        const port = uci.get_first('iperf3', 'iperf3', 'port') || DEFAULT_PORT;
        const args = ['-c', server, '-p', port];
        if (uci.get_first('iperf3', 'iperf3', 'reverse') === '1') args.push('-R');
        ui.showModal(_('iPerf3 Test Results'), [E('p', _('running... Will take a bit...')), dismissButton()]);
        return fs.exec('/usr/bin/iperf3', args).then(checkedOutput).then(output => {
            ui.showModal(_('iPerf3 Test Results'), [E('pre', [output]), dismissButton()]);
        }).catch(error => {
            ui.showModal(_('iPerf3 Test Results'), [E('pre', [error.message]), dismissButton()]);
            ui.addNotification(null, _('Failed to start iPerf3 test: ') + error.message, 'error');
        });
    },

    handleStartServer: function() {
        const port = uci.get_first('iperf3', 'iperf3', 'port') || DEFAULT_PORT;
        return fs.exec('/usr/bin/iperf3', ['-s', '-D', '-p', port]).then(checkedOutput).then(() => {
            ui.addNotification(null, _('iPerf3 server started successfully'), 'info');
        }).catch(error => {
            ui.addNotification(null, _('Failed to start iPerf3 server: ') + error.message, 'error');
        });
    },

    handleStopServer: function() {
        return fs.exec('/usr/bin/killall', ['iperf3']).then(checkedOutput).then(() => {
            ui.addNotification(null, _('iPerf3 stopped successfully'), 'info');
        }).catch(error => {
            ui.addNotification(null, _('Failed to stop iPerf3 server: ') + error.message, 'error');
        });
    }
});
