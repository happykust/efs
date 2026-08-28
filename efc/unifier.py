# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

import datetime
import json
from pathlib import Path

from .utils import opener

_PKG_DIR = Path(__file__).parent.resolve()


def get_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return elem.get('value', '')
    return ''

def eval_prop(components, name):
    vals = set()
    for comp in components:
        vals.add(get_prop(comp.get('properties', []), name))
    if 'yes' in vals:
        return 'yes'
    if 'indirect' in vals:
        return 'indirect'
    if vals == {'no'}:
        return 'no'
    return ''


def run(args):
    with open(_PKG_DIR / 'schemas' / 'schema.json') as f:
        schema = json.load(f)
        keys = set(schema['properties']).intersection(schema['$defs']['component']['properties'])
        if 'version' in keys:
            keys.remove('version')
        if 'name' in keys:
            keys.remove('name')
        if 'type' in keys:
            keys.remove('type')

    all_components = []
    for fn in args.input:
        data, encoding = opener(fn)
        new_data = data['metadata']['component'].copy()
        for key in keys:
            if key in data:
                new_data[key] = data[key]
        if not 'properties' in new_data:
            new_data['properties'] = []
        if not get_prop(new_data.get('properties', []), 'GOST:attack_surface'):
            new_data['properties'].append({
                "name": 'GOST:attack_surface',
                "value": eval_prop(data.get('components', []), 'GOST:attack_surface')
            })
        if not get_prop(new_data.get('properties', []), 'GOST:security_function'):
            new_data['properties'].append({
                "name": 'GOST:security_function',
                "value": eval_prop(data.get('components', []), 'GOST:security_function')
            })
        all_components.append(new_data)

    output_data = {
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "component": {
            "type": "application",
            "name": args.app_name,
            "version": args.app_version,
            "manufacturer": {
                "name": args.manufacturer
            }
        }
      },
      "components": all_components
    }

    with open(args.output, 'w', encoding=encoding) as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
