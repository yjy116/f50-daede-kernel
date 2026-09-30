/* Explicit in-memory UCI boundary double for public build fixtures only. */
import { readfile } from 'fs';
export function cursor() {
	const data = json(readfile(getenv('F50_UCI_FIXTURE')));
	return {
		load: function(name) { if (name !== 'homeproxy') die('Unexpected config'); return true; },
		get: function(name, section, option) { return data[section]?.[option]; },
		get_all: function(name, section) { return data[section]; },
		foreach: function(name, kind, callback) {
			for (let section in data)
				if (data[section]['.type'] === kind) callback(data[section]);
		}
	};
};
