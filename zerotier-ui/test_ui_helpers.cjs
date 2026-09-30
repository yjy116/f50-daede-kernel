'use strict';
const fs = require('node:fs');
const path = require('node:path');
const resourceRoot = path.join(__dirname, 'root/www/luci-static/resources');

function element(tag, attributes, children) {
    return { tag, attributes: attributes || {}, children: children || [],
        appendChild(child) { this.children.push(child); } };
}

function loadModule(file, dependencies) {
    const source = fs.readFileSync(path.join(resourceRoot, file), 'utf8');
    return new Function(...Object.keys(dependencies), source)(...Object.values(dependencies));
}

function option(definition) {
    return { ...definition, choices: [],
        value(value) { this.choices.push(value); },
        depends(value) { this.dependency = value; } };
}

function formBoundary(sections, data) {
    class Map {
        constructor() { this.data = data; }
        section(kind, ...args) {
            const section = { kind, args, map: this, options: [], option(...definition) {
                const [type, name, title, description] = definition;
                const field = option({ type, name, title, description });
                field.map = this.map;
                this.options.push(field);
                return field;
            } };
            sections.push(section);
            return section;
        }
        render() { return Promise.resolve(element('div', {}, sections)); }
    }
    return { Map, NamedSection: 'named', GridSection: 'grid', TypedSection: 'typed',
        Flag: 'flag', Value: 'value', Button: 'button' };
}

function configurationHarness(data = {}) {
    const sections = [];
    const form = formBoundary(sections, data);
    const common = loadModule('zerotier/common.js', { baseclass: { extend: x => x } });
    const appearance = loadModule('zerotier/appearance.js', {
        baseclass: { extend: x => x }, E: element, L: { resource: name => '/luci-static/resources/' + name }
    });
    const runtime = { statusSection(map) { return map.section(form.TypedSection); } };
    const view = loadModule('view/zerotier/config.js', {
        form, common, runtime, appearance, view: { extend: x => x }, E: element, _: x => x,
        window: { open() { throw new Error('Unexpected navigation during render'); } }
    });
    return { sections, view };
}

module.exports = { configurationHarness, loadModule, element };
