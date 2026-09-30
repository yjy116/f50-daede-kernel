/* No real ubus connection or network operation is made by this fixture. */
export function connect() {
	return { call: function(object, method, arguments) {
		if (object !== 'network.interface' || method !== 'status') die('Unexpected ubus request');
		return { 'dns-server': ['192.0.2.53'] };
	}};
}
