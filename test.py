from cbc_sdk.rest_api import CBCloudAPI
from cbc_sdk.platform import Device, Process
from cbc_sdk.base import QueryBuilder
from cbc_sdk.endpoint_standard import EnrichedEvent
from cbc_sdk.utils import convert_from_cb, convert_to_cb
import argparse


class build_query:
    '''Takes filters and turns them into an appropriate CBC query'''
    PARAMETER_MAPPING = {
        # Enriched event parameters to filter names
        'device_name': 'device_name',
        'device_id': 'device_id',
        'cmdline': 'process_cmdline',
        'process_name': 'process_name',
        'ipaddr': 'event_network_remote_ipv4',
        'domain_name': 'netconn_domain',
        'event_type': 'enriched_event_type',
        'event': 'event_type',
        'username': 'process_username',

    }

    def __init__(self, api, query_type, rows, kwargs): #this is where we define the instance
        #set all of the filter name 
        self.type=query_type
        self.args=kwargs
        self.rows=rows
        self.api=api
        #for key, value in kwargs.items():
            #setattr(self, key, value)

    def make_query(self):
        if self.type == 'enriched_event':
            #first = True
            query = self.api.select(EnrichedEvent).set_rows(self.rows)
            for key,value in self.args.items():
                if key in ('event_type'):
                    value = value.upper()
                # make lowercase
                else:
                    value = value.lower()
                keyname = self.PARAMETER_MAPPING[key] # map to the actual filter name
                filter = f'{keyname}:{value}'
                # make uppercase
                print(filter)
                query.and_(filter)

        elif type == 'process': # wip
            None
        elif type == 'alert': # wip 
            None
        return query

def argument_parser():
    parser = argparse.ArgumentParser(
        prog='HUNT',
        description='HUNT is a tool that allows you to access the CBC API. Use the parameters below to indicate what APIs you would like to call. \n\
        Make sure that you have the proper authentication file in place, as found in https://carbon-black-cloud-python-sdk.readthedocs.io/en/latest/authentication/',
        epilog='Author: Stephen Hurd\tVersion:0.1\tDate:03/27/2023'
    )
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='Turn on verbose logging. Enables debug messages. This can be very noisy')
    parser.add_argument('-d', '--devices', required=False, action='store_true', help='Export all of the devices to a csv file.')
    parser.add_argument('-q', '--query', required=False, action='store_true', help='List all instances of ir_agent.exe')
    parser.add_argument('-n', '--netconn', required=False, action='store_true', help='Export network connection events')

    sub_parsers = parser.add_subparsers(title='subcommands', description='The following subcommands are supported:', help='Use these sub commands to start dialing in your query', dest='command')

    #Enriched events query
    enriched_events_query = sub_parsers.add_parser('query_enriched_events', help='Start building an enriched event query with supported filters')
    enriched_events_query.add_argument('--device_name', required=False, action='store', help='Filter by device name')
    enriched_events_query.add_argument('--cmdline', required=False, action='store', help='Filter by command line')
    enriched_events_query.add_argument('--process_name', required=False, action='store', help='Filter by process name')
    enriched_events_query.add_argument('--ipaddr', required=False, action='store', help='Filter by IP address')
    enriched_events_query.add_argument('--domain_name', required=False, action='store', help='Filter by domain name')
    enriched_events_query.add_argument('--event_type', required=False, action='store', help='Filter by enriched event type')
    enriched_events_query.add_argument('--event', required=False, action='store', help='Filter by event type')
    enriched_events_query.add_argument('--username', required=False, action='store', help='Filter by username')

    process_query = sub_parsers.add_parser('query_processes', help='Start building a process query with supported filters')
    process_query.add_argument('--device_name', required=False, action='store', help='Filter by device name')
    process_query.add_argument('--cmdline', required=False, action='store', help='Filter by command line')
    process_query.add_argument('--process_name', required=False, action='store', help='Filter by process name')
    process_query.add_argument('--addr', required=False, action='store', help='Filter by IP address')
    process_query.add_argument('--process_hash', required=False, action='store', help='Filter by process hash')
    process_query.add_argument('--parent_hash', required=False, action='store', help='Filter by parent process hash')
    process_query.add_argument('--signed', required=False, action='store_true', help='Filter by signed or not signed (true/false)')

    ''' # Need to work on this to find proper filters
    alerts_query = sub_parsers.add_parser('query_alerts', help='Start building an alerts query with supported filters')
    alerts_query.add_argument('--device_name', required=False, action='store', help='Filter by device name')
    alerts_query.add_argument('--cmdline', required=False, action='store', help='Filter by command line')
    alerts_query.add_argument('--process_name', required=False, action='store', help='Filter by process name')
    alerts_query.add_argument('--ipv4', required=False, action='store', help='Filter by IP address')
    alerts_query.add_argument('--process_hash', required=False, action='store', help='Filter by process hash')
    alerts_query.add_argument('--signed', required=False, action='store_true', help='Filter by signed or not signed (true/false)')
    '''
    #parser.add_argument('-v', '--verbose', required=False, action=, help='')

    args = parser.parse_args()
    #args2 = enriched_events_query.parse_args()
    args2 = enriched_events_query.parse_args()
    args3 = process_query.parse_args()

    return args, args2, args3

args,args2,args3 = argument_parser()
#temp = vars(args)
print(vars(args))
print(vars(args2))
print(vars(args3))

"""query_args_dict = {}
for key in temp:
    if (key not in ('verbose', 'devices', 'query', 'netconn')) and (temp[key] != None):
        query_args_dict[key] = temp[key]"""


api = CBCloudAPI(profile='default')
"""d = {
    "key": "value",
    "ley2": "value2"
}

filters = {
    'device_name': 'GDC8APPD2021',    
    'event_type': 'system_api_call',
    #'process_name': 'conhost.exe',
}"""
"""query = build_query(query_type='enriched_event', api=api, rows=2, kwargs=query_args_dict)

r = query.make_query()
print(len(r))
for i in r:
    print(i)
"""


