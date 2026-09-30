/* Actual running-kernel configuration; never infer builtins from dummy modules. */
function parseBuiltinFeatures(content) {
	let result = {};
	for (let line in split(content || '', '\n'))
		if (line === 'CONFIG_TUN=y' || line === 'CONFIG_NFT_TPROXY=y')
			result[split(line, '=')[0]] = true;
	return result;
}

function readBuiltinFeatures() {
	const fd = popen('/bin/zcat /proc/config.gz');
	if (!fd)
		return {};
	const content = fd.read('all');
	const status = fd.close();
	return status === 0 ? parseBuiltinFeatures(content) : {};
}
