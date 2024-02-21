#############################################################
#                                                           #
# FMC Multi-Rule Duplicator                                 #
# Author: Brennan Bouchard                                  #
#                                                           #
# Date: 2/20/24                                             #
#                                                           #
#############################################################
import argparse
import time
from rest import FmcSession
import log
import json

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
parser.add_argument('--log_name', help='Name of log file to write',
                    required=False, default='logs')
parser.add_argument('--log_directory', help='Name directory path for the log file',
                    required=False, default='./logs')

args = parser.parse_args()
logger = log.get_logger(log_name=f'{args.log_name}.log', log_path=args.log_directory)
logger.info('Starting FMC rule duplicator')
logger.info('Creating FMC Session')
fmc = FmcSession(hostname=args.hostname,
                 username=args.username,
                 password=args.password)


def get_path_type(object_type):
    if object_type == 'Network':
        return 'networks'
    if object_type == 'Range':
        return 'ranges'
    if object_type == 'Host':
        return 'hosts'


def create_get_object(object_name, object_type, object_value):
    if object_name in updated_objects.keys():
        return updated_objects[object_name]
    data = {
        'type': object_type,
        'name': object_name,
        'value': object_value
    }
    path_type = get_path_type(object_type)
    obj = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/{path_type}', data=data)
    if not obj:
        obj = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/object/{path_type}?filter=nameOrValue:{object_name}')
        if obj:
            obj = obj['items'][0]
            if 'overridable' not in obj.keys():
                obj['overridable'] = False
    updated_objects.update({obj['name']: {'id': obj['id'], 'name': obj['name'],
                                          'overridable': obj['overridable'], 'type': obj['type']}})
    return obj


acp = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies', name=args.acp)['items'][0]
logger.info(f'Captured access control policy details for: {args.acp}')
rules_summary = fmc.get(f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies/{acp["id"]}/accessrules')[
    'items']
logger.info(f'Captured access control policy rules details for: {args.acp}')
if '-' in args.rules:
    rules_split = args.rules.split('-')
    rule_numbers = range(int(rules_split[0]), int(rules_split[1]))
else:
    rule_numbers = args.rules.split(',')
new_rules = []
updated_objects = {}
for r in rule_numbers:
    rule_number = int(r) - 1
    rule = fmc.get(
        f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies/{acp["id"]}/accessrules/{rules_summary[rule_number]["id"]}')
    logger.info(f'Captured access control policy details for: {args.acp} RULE: {rules_summary[rule_number]["id"]}')
    if 'sourceNetworks' in rule.keys():
        src = []
        for s in rule['sourceNetworks']['objects']:
            if s['name'] == args.modify_object:
                src.append(create_get_object(args.object_new_name, s['type'], args.object_new_value))
            else:
                src.append(s)
        rule['sourceNetworks']['objects'] = src
    if 'destinationNetworks' in rule.keys():
        dst = []
        for d in rule['destinationNetworks']['objects']:
            if d['name'] == args.modify_object:
                dst.append(create_get_object(args.object_new_name, d['type'], args.object_new_value))
            else:
                dst.append(d)
        rule['destinationNetworks']['objects'] = dst
    del rule['metadata']
    del rule['links']
    del rule['id']
    timestr = time.strftime("%H%M%S", time.localtime())
    rule['name'] = f'COPIED-{timestr}-{rule["name"]}'
    new_rule = fmc.post(f'/fmc_config/v1/domain/{fmc.domain_uuid}/policy/accesspolicies/{acp["id"]}/accessrules', data=rule)
    time.sleep(.3)
    if not new_rule:
        logger.info(f'Unable to create rule, use the following JSON to manually create it:\n {json.dumps(rule)}\n')
    new_rules.append(new_rule)

logger.info(f'Rule generation complete, added {len(new_rules)} rules')
logger.info(f'Rules JSON: \n{json.dumps(new_rules)}\n')
if updated_objects:
    logger.info(f'Updated Object JSON: \n{json.dumps(updated_objects)}\n')
