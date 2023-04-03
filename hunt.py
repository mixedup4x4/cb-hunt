"""
This script will use the supplied 'default' api credentials to download all of the 
devices to a CSV file.
"""
import sys
# ensure Python version is compatible (Python v2 will always error out)
if sys.version_info.major == 3 and sys.version_info.minor < 9:
    print(f'Python 3.9+ is required to run HUNT (current: {sys.version_info.major}.{sys.version_info.minor})')
    exit(1)
from cbc_sdk.rest_api import CBCloudAPI
from cbc_sdk.platform import Device, Process
from cbc_sdk.endpoint_standard import EnrichedEvent
from cbc_sdk.utils import convert_from_cb, convert_to_cb
import logging as l
import argparse
import csv
from datetime import datetime
from tqdm import tqdm
import asyncio

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
                l.debug(f'Applied the filter: "{filter}"')
                query.and_(filter)

        elif type == 'process': # wip
            None
        elif type == 'alert': # wip 
            None
        return query  

def api_connect(p):
    try:
        api = CBCloudAPI(profile=p)
        l.debug('Got api object: ' + str(api))

    except Exception as e:
        l.error(f'Failed to get api object: {e}')
        api = None

    return api

def download_devices(api):        
        try:
            devices = api.select(Device).set_os(["WINDOWS"]).set_status(["ALL"]).download()

            l.info('Writing devices.csv')
            with open('devices.csv', 'w') as csvfile:
                for device in devices:
                    w = csvfile.write(device)
            l.info('Finished writing devices.csv')

        except Exception as e:
            l.error(f'Failed to download devices: {e}')

def get_enriched_events(query, export_template, output_file): #WIP
    """
    Function that will retrieve all NETWORK events for a specified process
    export events to a csv
    """
    #query = api.select(EnrichedEvent).where(enriched_event_type="NETWORK").set_rows(10000)
    try:
        # get the detailed output in an asynchronous fashion 
        results = [result.get_details(async_mode=True) for result in query]
        l.info(f'Found {len(results)} results')
        """
        results = [] #this will be an array of furtures, containing .results() for .get_details()
        for result in query:
            results.append(result.get_details(async_mode=True))
            #results.append(result)
            i+=1
        """

    except Exception as e:
        l.error(f'There was a problem with retrieving the results: {e}')

    finally:        
        l.info('Opening netconn.csv for writing')
        with open(output_file, 'w', newline='',encoding='utf-8') as csvfile:
            #Headers
            fields = export_template
            """fields = [ #need to convert ingress time
                'backend_timestamp','ingress_time','device_name',
                'device_external_ip','event_network_local_ipv4','netconn_local_port','event_network_remote_ipv4','event_network_remote_port','event_network_inbound',
                'event_network_protocol','netconn_domain','netconn_location','netconn_actions',
                'process_name','process_start_time','process_cmdline','process_username','process_effective_reputation','process_pid','process_guid','process_sha256',
                'parent_name','parent_pid','parent_hash','parent_reputation',
                'ttp','device_id', 'enriched_event_type', 'event_type','event_id','event_description'
            ]"""
            
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            try:
                l.info(f'Starting to iterate available results')
                for result in tqdm(results, unit='results', desc='getting detailed results'):
                    netconn = result.result()
                    row = {}
                    for field in fields:
                        try:
                            value = getattr(netconn, field)
                            # normalizing dates
                            if field == "ingress_time":
                                value = int(str(value)[:-3])
                                value = datetime.fromtimestamp(value).isoformat(sep=" ",timespec='seconds')
                            
                            if (field == "backend_timestamp") or (field == "process_start_time") or (field == "device_timestamp"):
                                value = convert_from_cb(value).replace(tzinfo=None).isoformat(sep=" ",timespec='seconds')

                            # fixing the domains
                            if (field == "netconn_domain"):
                                value = value.replace('..','.')

                            if type(value) is list:
                                if type(value[0]) is int:
                                    row[field] = value[0]
                                else:
                                    row[field] = ', '.join(value)
                            else:
                                row[field] = value
                        except:
                            row[field] = ""

                    try:
                        writer.writerow(row)
                    except Exception as e:
                        l.error(f'Something went wrong while writing the csv: {e}')

                l.info('Finished fetching the results')
        
            except Exception as e:
                l.error(f'There was a problem retrieving the futured results: {e}')
                l.warning('cancelling pending tasks and exiting..')
                for result in results:
                    result.cancel()

                csvfile.close()

            except KeyboardInterrupt:
                l.warning('Recieved keyboard interrupt.. cancelling pending tasks and exiting..')
                # find all futures still running and cancel them
                for result in results:
                    result.cancel()

                csvfile.close()

        l.info('Finished writing netconn.csv')

def argument_parser():
    parser = argparse.ArgumentParser(
        prog='python3.exe hunt.py',
        description='HUNT is a tool that allows you to access the CBC API. Use the parameters below to indicate what APIs you would like to call. \n\
        Make sure that you have the proper authentication file in place, as found in https://carbon-black-cloud-python-sdk.readthedocs.io/en/latest/authentication/',
        epilog='Author: Stephen Hurd\tVersion: 0.2\tDate: 04/1/2023'
    )
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='Turn on verbose logging. Enables debug messages. This can be very noisy')
    parser.add_argument('-d', '--devices', required=False, action='store_true', help='Export all of the devices to a csv file.')
    parser.add_argument('-q', '--query', required=False, action='store_true', help='List all instances of ir_agent.exe')
    parser.add_argument('-n', '--netconn', required=False, action='store_true', help='Export network connection events')
    parser.add_argument('-o', '--output', required=False, default='output.csv', action='store', help='File name or path to store the results in.')

    sub_parsers = parser.add_subparsers(title='subcommands', description='The following subcommands are supported:', help='Use these sub commands to start dialing in your query', dest='command')

    #Enriched events query
    enriched_events_query = sub_parsers.add_parser('query_enriched_events', help='Start building an enriched event query with supported filters')
    enriched_events_query.add_argument('--device_name', required=False, action='store', help='Filter by device name')
    enriched_events_query.add_argument('--cmdline', required=False, action='store', help='Filter by command line')
    enriched_events_query.add_argument('--process_name', required=False, action='store', help='Filter by process name')
    enriched_events_query.add_argument('--ipaddr', required=False, action='store', help='Filter by IP address')
    enriched_events_query.add_argument('--domain_name', required=False, action='store', help='Filter by domain name')
    enriched_events_query.add_argument('--event_type', required=False, default=None, action='store', help='Filter by enriched event type')
    enriched_events_query.add_argument('--event', required=False, action='store', help='Filter by event type')
    enriched_events_query.add_argument('--username', required=False, action='store', help='Filter by username')
    enriched_events_query.add_argument('--rows', required=False, type=int, default=10000, choices=range(0, 10001), action='store', help='Number of rows to get. Default is the maximum - 10000')

    process_query = sub_parsers.add_parser('query_processes', help='Start building a process query with supported filters')
    process_query.add_argument('--device_name', required=False, action='store', help='Filter by device name')
    process_query.add_argument('--cmdline', required=False, action='store', help='Filter by command line')
    process_query.add_argument('--process_name', required=False, action='store', help='Filter by process name')
    process_query.add_argument('--addr', required=False, action='store', help='Filter by IP address')
    process_query.add_argument('--process_hash', required=False, action='store', help='Filter by process hash')
    process_query.add_argument('--parent_hash', required=False, action='store', help='Filter by parent process hash')
    process_query.add_argument('--signed', required=False, action='store_true', help='Filter by signed or not signed (true/false)')
    process_query.add_argument('--rows', required=False, type=int, default=10000, choices=range(0, 10001), action='store', help='Number of rows to get. Default is the maximum - 10000')

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
    temp = vars(args)
    query_filter_dict = {}
    for key in temp:
        if (key not in ('verbose', 'devices', 'query', 'netconn', 'rows', 'command', 'output')) and (temp[key] != None):
            query_filter_dict[key] = temp[key]
    return args, query_filter_dict

def main():
    # ARGUMENT PARSER
    args, query_filter_dict = argument_parser()

    # LOGGING CONFIGURATION
    if(args.verbose):
        l.basicConfig(level=l.DEBUG,
                    format="%(asctime)s [%(levelname)s]   \t%(message)s",
                    handlers=[l.FileHandler("debug.log"),
                                l.StreamHandler()])
    else:
        l.basicConfig(level=l.INFO,
                    format="%(asctime)s [%(levelname)s]   \t%(message)s",
                    handlers=[l.FileHandler("debug.log"),
                                l.StreamHandler()])

    # Table template configurations
    TABLE_TEMPLATE = {
        'netconn_template': [
            'backend_timestamp','ingress_time','device_name',
            'device_external_ip','event_network_local_ipv4','netconn_local_port','event_network_remote_ipv4','event_network_remote_port','event_network_inbound',
            'event_network_protocol','netconn_domain','netconn_location','netconn_actions',
            'process_name','process_start_time','process_cmdline','process_username','process_effective_reputation','process_pid','process_guid','process_sha256',
            'parent_name','parent_pid','parent_hash','parent_reputation',
            'ttp','device_id','enriched_event_type','event_type','event_id','event_description'
        ],
        'api_call_template': [ # needs to be vetted
            'backend_timestamp','crossproc_action','crossproc_api','crossproc_target','device_external_ip',
            'device_group','device_group_id','device_id','device_installed_by','device_internal_ip',
            'device_location','device_name','device_os','device_os_version','device_policy','device_policy_id',
            'device_target_priority','device_timestamp','document_guid','enriched','enriched_event_type',
            'event_description','event_id','event_report_code','event_threat_score','event_type','ingress_time',
            'legacy','org_id','parent_effective_reputation','parent_effective_reputation_source','parent_guid',
            'parent_hash','parent_name','parent_pid','parent_reputation','process_cmdline','process_cmdline_length',
            'process_effective_reputation','process_effective_reputation_source','process_guid','process_hash',
            'process_name','process_pid','process_reputation','process_sha256','process_start_time','process_username','ttp'
        ],
        'create_process_template': [ # needs to be vetted
            'backend_timestamp','childproc_cmdline','childproc_cmdline_length','childproc_effective_reputation',
            'childproc_effective_reputation_source','childproc_guid','childproc_hash','childproc_name','childproc_pid',
            'childproc_reputation','device_external_ip','device_group','device_group_id','device_id',
            'device_installed_by','device_internal_ip','device_location','device_name','device_os','device_os_version',
            'device_policy','device_policy_id','device_target_priority','device_timestamp','document_guid','enriched',
            'enriched_event_type','event_description','event_id','event_report_code','event_type','ingress_time',
            'legacy','org_id','parent_effective_reputation','parent_effective_reputation_source','parent_guid',
            'parent_hash','parent_name','parent_pid','parent_reputation','process_cmdline','process_cmdline_length',
            'process_effective_reputation','process_effective_reputation_source','process_guid','process_hash',
            'process_name','process_pid','process_reputation','process_sha256','process_start_time','process_username','ttp'
        ],
        'registry_access_template': [ # needs to be vetted
            'attack_tactic','attack_technique','backend_timestamp','childproc_count','crossproc_count',
            'device_external_ip','device_group','device_group_id','device_id','device_installed_by',
            'device_internal_ip','device_location','device_name','device_os','device_os_version',
            'device_policy','device_policy_id','device_sensor_version','device_target_priority','device_timestamp',
            'document_guid','enriched_event_type','event_description','event_id','event_report_code','event_type',
            'filemod_count','ingress_time','modload_count','netconn_count','org_id','parent_cmdline',
            'parent_cmdline_length','parent_effective_reputation','parent_effective_reputation_source',
            'parent_guid','parent_hash','parent_name','parent_pid','parent_publisher','parent_publisher_state',
            'parent_reputation','process_cmdline','process_cmdline_length','process_company_name',
            'process_effective_reputation','process_effective_reputation_source','process_elevated',
            'process_file_description','process_guid','process_hash','process_integrity_level',
            'process_internal_name','process_name','process_original_filename','process_pid','process_privileges',
            'process_product_name','process_product_version','process_publisher','process_publisher_state',
            'process_reputation','process_service_name','process_sha256','process_start_time','process_username',
            'regmod_action','regmod_count','regmod_name','scriptload_count','ttp'
        ],
        'general_template': [
            'attack_tactic','attack_technique','backend_timestamp','childproc_cmdline','childproc_cmdline_length',
            'childproc_count','childproc_effective_reputation','childproc_effective_reputation_source',
            'childproc_guid','childproc_hash','childproc_name','childproc_pid','childproc_reputation',
            'crossproc_action','crossproc_api','crossproc_count','crossproc_target','device_external_ip',
            'device_group','device_group_id','device_id','device_installed_by','device_internal_ip',
            'device_location','device_name','device_os','device_os_version','device_policy','device_policy_id',
            'device_sensor_version','device_target_priority','device_timestamp','document_guid','enriched',
            'enriched_event_type','event_description','event_id','event_network_inbound',
            'event_network_local_ipv4','event_network_protocol','event_network_remote_ipv4',
            'event_network_remote_port','event_report_code','event_threat_score','event_type',
            'filemod_count','ingress_time','legacy','modload_count','netconn_actions','netconn_count',
            'netconn_domain','netconn_local_port','netconn_location','org_id','parent_cmdline',
            'parent_cmdline_length','parent_effective_reputation','parent_effective_reputation_source',
            'parent_guid','parent_hash','parent_name','parent_pid','parent_publisher','parent_publisher_state',
            'parent_reputation','process_cmdline','process_cmdline_length','process_company_name',
            'process_effective_reputation','process_effective_reputation_source','process_elevated',
            'process_file_description','process_guid','process_hash','process_integrity_level',
            'process_internal_name','process_name','process_original_filename','process_pid',
            'process_privileges','process_product_name','process_product_version','process_publisher',
            'process_publisher_state','process_reputation','process_service_name','process_sha256',
            'process_start_time','process_username','regmod_action','regmod_count','regmod_name',
            'scriptload_count','ttp'
        ]
    }
    if args.event_type:
        t = args.event_type.lower()
        if t == 'network':
            export_template = TABLE_TEMPLATE['netconn_template']
            l.info(f'Chose the netconn_template for the output file')
        elif t == 'system_api_call':
            export_template = TABLE_TEMPLATE['api_call_template']
            l.info(f'Chose the api_call_template for the output file')
        elif t == 'create_process':
            export_template = TABLE_TEMPLATE['create_process_template']
            l.info(f'Chose the create_process_template for the output file')
        else:
            export_template = TABLE_TEMPLATE['general_template']
            l.info(f'Chose the general_template for the output file')
    else:
        export_template = TABLE_TEMPLATE['general_template']
        l.info(f'Chose the general_template for the output file')
    

    #Obligatory ASCII art
    print(f'{bcolors.HEADER}\
######################################\n\
  ___ ___  ____ _____________________ \n\
 /   |   \|    |   \      \__    ___/ \n\
/    ~    \    |   /   |   \|    |    \n\
\    Y    /    |  /    |    \    |    \n\
 \___|_  /|______/\____|__  /____|    \n\
       \/        @HurdDFIR\/          \n\
######################################{bcolors.ENDC}')

    api = api_connect('default')

    if(args.devices):
        download_devices(api)

    if(args.command == 'query_enriched_events'):
        query = build_query(api=api,query_type='enriched_event',rows=args.rows,kwargs=query_filter_dict)
        results = query.make_query()
        get_enriched_events(results,export_template=export_template,output_file=args.output)
    
    if(args.command == 'query_processes'):
        l.error('This functionality has not been implemented yet. Please be patient while I work hard to get this function implemented properly.')
        exit()

if __name__ == "__main__":
    main()