import sys
import argparse
import time
from rest import FmcSession


timestr = time.strftime("%Y%m%d-%H%M%S")
parser = argparse.ArgumentParser(description='Secure Firewall Multi-Rule Duplicator.', prog='FMC Rule Duplicator')

parser.add_argument('--hostname', help='Hostname or IP of FMC', required=True)
parser.add_argument('--username', help='Username for authenticating with FMC', required=True)
parser.add_argument('--password', help='Password for authenticating with FMC', required=True)
parser.add_argument('--acp', help='Name of access control policy to duplicate rules from', required=False)
parser.add_argument('--rules', help='Comma seperated list of rule numbers without spaces', required=False)
parser.add_argument('--modify_object', help='Object name to be modified, must be IP, Network, Range, or FQDN',
                    required=False)
parser.add_argument('--object_new_name', help='Previous value to be modified', required=False)
parser.add_argument('--object_new_value', help='Updated value of object', required=False)

args = parser.parse_args()
fmc = FmcSession(hostname=args.hostname,
                 username=args.username,
                 password=args.password)


acp = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies', name=args.acp)['items'][0]
rules_summary = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies/{acp["id"]}/accessrules')[
    'items']
rule_numbers = args.rules.split(',')
new_rules = []
updated_objects = {}
for r in rule_numbers:
    rule = fmc.get(
        f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies/{acp["id"]}/accessrules/{rules_summary[int(r) - 1]["id"]}')
    if 'sourceNetworks' in rule.keys():
        src = []
        for s in rule['sourceNetworks']['objects']:
            if s['name'] == args.modify_object:
                if s['name'] not in updated_objects.keys():
                    if s['type'] == 'Network':
                        old = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/networks/{s["id"]}')
                        data = {
                            'type': 'Network',
                            'name': args.object_new_name,
                            'value': args.object_new_value
                        }
                        try:
                            new = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/networks', data=data)
                        except:
                            new = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/networks',
                                          name=args.object_new_name)
                        src.append({'id': new['id'], 'name': new['name'], 'overridable': new['overridable'],
                                    'type': new['type']})
                        updated_objects.update({new['name']: {'id': new['id'], 'name': new['name'],
                                                              'overridable': new['overridable'], 'type': new['type']}})
                    elif s['type'] == 'Host':
                        old = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/hosts/{s["id"]}')
                        data = {
                            'type': 'Host',
                            'name': args.object_new_name,
                            'value': args.object_new_value
                        }
                        new = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/hosts', data=data)
                        src.append({'id': new['id'], 'name': new['name'], 'overridable': new['overridable'],
                                    'type': new['type']})
                        updated_objects.update({new['name']: {'id': new['id'], 'name': new['name'],
                                                              'overridable': new['overridable'], 'type': new['type']}})
                    elif s['type'] == 'Range':
                        old = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/ranges/{s["id"]}')
                        data = {
                            'type': 'Range',
                            'name': args.object_new_name,
                            'value': args.object_new_value
                        }
                        new = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/ranges', data=data)
                        src.append({'id': new['id'], 'name': new['name'], 'overridable': new['overridable'],
                                    'type': new['type']})
                        updated_objects.update({new['name']: {'id': new['id'], 'name': new['name'],
                                                              'overridable': new['overridable'], 'type': new['type']}})
                else:
                    src.append(updated_objects[args.modify_object])
            else:
                src.append(s)
        rule['sourceNetworks']['objects'] = src
    if 'destinationNetworks' in rule.keys():
        dst = []
        for d in rule['destinationNetworks']['objects']:
            if d['name'] == args.modify_object:
                if d['name'] not in updated_objects.keys():
                    if d['type'] == 'Network':
                        old = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/networks/{d["id"]}')
                        data = {
                            'type': 'Network',
                            'name': args.object_new_name,
                            'value': args.object_new_value
                        }
                        try:
                            new = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/networks', data=data)
                        except:
                            new = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/networks',
                                          name=args.object_new_name)
                        dst.append({'id': new['id'], 'name': new['name'], 'overridable': new['overridable'],
                                    'type': new['type']})
                        updated_objects.update({new['name']: {'id': new['id'], 'name': new['name'],
                                                              'overridable': new['overridable'], 'type': new['type']}})
                    elif d['type'] == 'Host':
                        old = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/hosts/{d["id"]}')
                        data = {
                            'type': 'Host',
                            'name': args.object_new_name,
                            'value': args.object_new_value
                        }
                        new = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/hosts', data=data)
                        dst.append({'id': new['id'], 'name': new['name'], 'overridable': new['overridable'],
                                    'type': new['type']})
                        updated_objects.update({new['name']: {'id': new['id'], 'name': new['name'],
                                                              'overridable': new['overridable'], 'type': new['type']}})
                    elif d['type'] == 'Range':
                        old = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/ranges/{d["id"]}')
                        data = {
                            'type': 'Range',
                            'name': args.object_new_name,
                            'value': args.object_new_value
                        }
                        new = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/ranges', data=data)
                        dst.append({'id': new['id'], 'name': new['name'], 'overridable': new['overridable'],
                                    'type': new['type']})
                        updated_objects.update({new['name']: {'id': new['id'], 'name': new['name'],
                                                              'overridable': new['overridable'], 'type': new['type']}})
                else:
                    dst.append(updated_objects[args.modify_object])
            else:
                dst.append(d)
        rule['sourceNetworks']['objects'] = src
        rule['destinationNetworks']['objects'] = dst
    del rule['metadata']
    del rule['links']
    del rule['id']
    rule['name'] = f'COPIED-From-{rule["name"]}'
    new_rules.append(
        fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies/{acp["id"]}/accessrules', data=rule))
    print('hi')

print('hi')
