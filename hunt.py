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
from cbc_sdk.endpoint_standard import EnrichedEvent,EnrichedEventFacet
from cbc_sdk.utils import convert_from_cb, convert_to_cb
import logging
import argparse
import csv
from datetime import datetime, timedelta
import tqdm

TABLE_TEMPLATE = {
        'NETWORK': [ # Ready for use. Complete. Format described here. This is generally the same for the rest of the templates.
            # General info
            'device_timestamp','device_name',
            # Event specific info
            'device_external_ip','event_network_local_ipv4','netconn_local_port','event_network_remote_ipv4','event_network_remote_port','event_network_inbound',
            'event_network_protocol','netconn_domain','netconn_location','netconn_actions',
            # Process info
            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            # Parent info
            'parent_name','parent_cmdline','parent_hash',
            # General Event info
            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'  
        ],
        'SYSTEM_API_CALL': [ # Ready for use. Complete
            'device_timestamp','device_name',

            'crossproc_name','crossproc_action','crossproc_api',

            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            'parent_name','parent_cmdline','parent_hash',

            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'  
        ],
        'CREATE_PROCESS': [ # Ready for use. Complete
            'device_timestamp','device_name',

            'childproc_name','childproc_cmdline','childproc_guid','childproc_hash',

            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            'parent_name','parent_cmdline','parent_hash',

            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'  
        ],
        'REGISTRY_ACCESS': [ # Ready for use. Complete
            'device_timestamp','device_name',

            'regmod_name','regmod_action',
            'childproc_count','crossproc_count','filemod_count','modload_count','netconn_count','regmod_count','scriptload_count',

            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            'parent_name','parent_cmdline','parent_hash',

            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'
        ],
        'FILE_CREATE': [ # Ready for use. Complete
            'device_timestamp','device_name',
            
            'filemod_name','filemod_action','file_scan_result','filemod_hash','filemod_publisher_state','filemod_reputation',

            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            'parent_name','parent_cmdline','parent_hash',

            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'  
        ],
        'INJECT_CODE': [ # Ready for use. Needs to be sorted/formatted
            'device_timestamp','device_name',

            'crossproc_action','crossproc_cmdline','crossproc_hash','sensor_action',
            'childproc_count','crossproc_count','filemod_count','modload_count','netconn_count','regmod_count','scriptload_count',

            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            'parent_name','parent_cmdline','parent_hash',

            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'            
        ],
        'OTHER_BEHAVIOR': [ # Ready for use. Needs to be sorted/formatted
            'device_timestamp','device_name',

            'childproc_count','crossproc_count','filemod_count','modload_count','netconn_count','regmod_count','scriptload_count',
            
            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            'parent_name','parent_cmdline','parent_hash',

            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'   
        ],
        'DATA_ACCESS': [ # not found in sample dataset - so pending some samples
    
        ],
        'POLICY_ACTION': [ # not found in sample dataset - so pending some samples
    
        ],
        'STATIC_SCAN': [ # not found in sample dataset - so pending some samples
            
        ],
        'general_template': [ # Still needs DATA_ACCESS, POLICY_ACTION, STATIC_SCAN specific items.
            # General info
            'device_timestamp','device_name',
            # Event specific info
            'device_external_ip','event_network_local_ipv4','netconn_local_port','event_network_remote_ipv4','event_network_remote_port','event_network_inbound',
            'event_network_protocol','netconn_domain','netconn_location','netconn_actions',

            'crossproc_name','crossproc_action','crossproc_api','crossproc_cmdline','crossproc_hash','sensor_action',
            'childproc_name','childproc_cmdline','childproc_guid','childproc_hash',
            'regmod_name','regmod_action',
            'filemod_name','filemod_action','file_scan_result','filemod_hash','filemod_publisher_state','filemod_reputation',

            'childproc_count','crossproc_count','filemod_count','modload_count','netconn_count','regmod_count','scriptload_count',
            # Process info
            'process_name','process_start_time','process_cmdline','process_username','process_guid','process_sha256',
            'process_original_filename','process_service_name','process_publisher','process_publisher_state','process_elevated','process_privileges','process_file_description',
            # Parent info
            'parent_name','parent_cmdline','parent_hash',
            # General Event info
            'enriched_event_type','event_type','event_id','attack_tactic','attack_technique','ttp','event_description'  
        ]
    }
# DEFINE GLOBAL LOGGER
l = logging.getLogger()

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

class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s [%(levelname)s]   \t%(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
        'ignore_color': format
    }

    def __init__(self, ignore_color=False):
        self.ignore_color = ignore_color

    def format(self, record):
        if self.ignore_color:
            log_fmt = self.FORMATS.get('ignore_color')
        else:
            log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

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
        'enriched_event_type': 'enriched_event_type',
        'event_type': 'event_type',
        'username': 'process_username',
        'start': 'start',
        'end': 'end',
        'window': 'window',
        '*': '*'
    }

    def __init__(self, api, query_type, rows, start, end, window=None, kwargs={}): #this is where we define the instance
        self.type=query_type
        if kwargs == {}:
            kwargs = {'*':'*'}
        self.args=kwargs
        self.rows=rows
        self.api=api
        self.start=start
        self.end=end
        if window:
            self.window=f'-{window}'
        else:
            self.window=window

    def make_query(self):
        if self.type == 'enriched_event':
            query = self.api.select(EnrichedEvent).set_rows(self.rows)
            for key,value in self.args.items():
                # make uppercase
                if key in ('enriched_event_type'):
                    if type(value) == list:
                        None
                    else:
                        value = value.upper()
                # make lowercase
                else:
                    if type(value) == list:
                        None
                    else:
                        value = value.lower()
                keyname = self.PARAMETER_MAPPING[key] # map to the actual filter name
                
                if type(value) == list:
                    temp = []
                    for v in value:
                        temp.append(f'{keyname}:"{v}"')
                        filter = '(' + ' OR '.join(temp) + ')'
                else:
                    filter = f'{keyname}:{value}'
                # make uppercase
                query.and_(filter)
                l.critical(f'Applied the filter: {filter}')
            
            if self.window:
                query.set_time_range(window=self.window)
                l.critical(f'Time Range set for: {self.window}')

            else:
                query.set_time_range(start=self.start,end=self.end)
                l.critical(f'Time Range set: {self.start} -> {self.end}')
                
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

def download_devices(api, output_file):        
        try:
            devices = api.select(Device).set_os(["WINDOWS"]).set_status(["ALL"]).download()

            l.info(f'Writing {output_file}')
            with open(output_file, 'w') as csvfile:
                for device in devices:
                    csvfile.write(device)
            l.info(f'Finished writing {output_file}')

        except Exception as e:
            l.error(f'Failed to download devices: {e}')

def get_enriched_events(query, export_template, output_file,verbose):
    """
    Function that will retrieve all NETWORK events for a specified process
    export events to a csv
    """
    try:
        # get the detailed output in an asynchronous fashion 
        results = [result.get_details(async_mode=True) for result in query]
        l.info(f'Found {len(results)} results')

    except Exception as e:
        l.error(f'There was a problem with retrieving the results: {e}')

    finally:        
        l.info(f'Opening {output_file} for writing')
        with open(output_file, 'w', newline='',encoding='utf-8') as csvfile:
            #Headers
            fields = export_template
            
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            try:
                l.info(f'Starting to iterate available results')
                for result in tqdm.tqdm(results, unit='result', desc='getting detailed results', disable=verbose):
                    r = result.result()
                    row = {}
                    for field in fields:
                        try:
                            value = getattr(r, field)
                            
                            # normalizing dates                          
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
                l.warning('Cancelling pending tasks and exiting..')
                for result in results:
                    result.cancel()

                csvfile.close()

            except KeyboardInterrupt:
                l.warning('Cancelling pending tasks and exiting..')
                # find all futures still running and cancel them
                for result in results:
                    result.cancel()

                csvfile.close()

        l.info(f'Finished writing {output_file}')

def get_processes(query, export_template, output_file, ioc_file): # WIP
    '''
    This function will search for processes by name, signature state or hash. 
    I intend to make this compatable with an input IOC file to do bulk searches for pre built queries
    '''

def argument_parser(author, version, date):
    parser = argparse.ArgumentParser(
        prog='python3.exe hunt.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='hunt.py allows an analyst to retrieve a wealth of information from the Carbon Black Cloud (CBC) API. This tool currently supports the following functionality:\n\
    - A full export of all devices in the tennant\n\
    - Customized enriched event queries (this is the "investigate" tab in the console GUI)\n\n\
**  Make sure that you have the proper authentication file in place, as found in https://carbon-black-cloud-python-sdk.readthedocs.io/en/latest/authentication/. \n\
    Currently, this program only supports file based authenticaiton.\n\
**  This may seem extremly slow compared to exporting searches from the console GUI. This is because this tool provides extended information that is not available \n\
    in the exports from the GUI. In my opinion, these details are very desirable in a Threat Hunting scenario, but maybe not in a Incident Response scenario. If \n\
    you are in a rush and don\'t need specific details, then I would reccomend using the GUI untill I implement simplified functionaility to this script. \n',
        epilog=f'Author: {author}\tVersion: {version}\tDate: {date}\n\n\
        Example usage:\n\
            python3.exe hunt.py -d -o devices.csv\n\
            python3.exe hunt.py -o [output.csv] investigate --device_name [hostname] --enriched_event_type [type] --ipaddr [IP]\n'
    )
    start_time = (datetime.utcnow() - timedelta(days=7)).isoformat(timespec='seconds') + 'Z'
    end_time = datetime.utcnow().isoformat(timespec='seconds') + 'Z'

    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='Turn on verbose logging. Enables debug messages. This can be very noisy')
    parser.add_argument('-d', '--devices', required=False, action='store_true', help='Export all of the devices to a csv file')
    parser.add_argument('-o', '--output', required=False, default='output.csv', action='store', help='File name or path to store the results in')

    sub_parsers = parser.add_subparsers(title='subcommands', description='The following subcommands are supported:', help='Use these sub commands to start dialing in your query', dest='command')

    #Enriched events query
    enriched_events_query = sub_parsers.add_parser('investigate', help='Start building an enriched event query with supported filters. Wildcards are supported.')
    enriched_events_query.add_argument('--device_name', required=False, nargs='+', action='store', help='Filter by device name')
    enriched_events_query.add_argument('--cmdline', required=False, nargs='+', action='store', help='Filter by command line')
    enriched_events_query.add_argument('--process_name', required=False, nargs='+', action='store', help='Filter by process name')
    enriched_events_query.add_argument('--ipaddr', required=False, nargs='+', action='store', help='Filter by IP address')
    enriched_events_query.add_argument('--domain_name', required=False, nargs='+', action='store', help='Filter by domain name')
    enriched_events_query.add_argument('--enriched_event_type', required=False, default=None, action='store', help='Filter by enriched event type')
    enriched_events_query.add_argument('--event_type', required=False, action='store', help='Filter by event type')
    enriched_events_query.add_argument('--username', required=False, nargs='+', action='store', help='Filter by username')
    enriched_events_query.add_argument('--rows', required=False, type=int, default=10000, action='store', help='Number of rows to get. Default is the maximum - 10000')
    enriched_events_query.add_argument('--start', required=False, default=start_time, action='store', help='Timestamp (UTC) to start searching at in ISO 8601 format')
    enriched_events_query.add_argument('--end', required=False, default=end_time, action='store', help='Timestamp (UTC) to end searching in ISO 8601 format')
    enriched_events_query.add_argument('--window', required=False, default=None, action='store', help='Relative time in the format of -1[y,d,h,m,s]. Default is -7d (days)')

    # still needs work on the function for this
    '''process_query = sub_parsers.add_parser('query_processes', help='Start building a process query with supported filters')
    process_query.add_argument('--device_name', required=False, action='store', help='Filter by device name')
    process_query.add_argument('--cmdline', required=False, action='store', help='Filter by command line')
    process_query.add_argument('--process_name', required=False, action='store', help='Filter by process name')
    process_query.add_argument('--addr', required=False, action='store', help='Filter by IP address')
    process_query.add_argument('--process_hash', required=False, action='store', help='Filter by process hash')
    process_query.add_argument('--parent_hash', required=False, action='store', help='Filter by parent process hash')
    process_query.add_argument('--signed', required=False, action='store_true', help='Filter by signed or not signed (true/false)')
    process_query.add_argument('--rows', required=False, type=int, default=10000, action='store', help='Number of rows to get. Default is the maximum - 10000')'''

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

    # Log configuration
    if(args.verbose):
        l.setLevel(logging.DEBUG)
        #log handlers
        screen = logging.StreamHandler()
        screen.setLevel(logging.DEBUG)
        screen.setFormatter(CustomFormatter())
        debug_log = logging.FileHandler('debug.log')
        debug_log.setLevel(logging.DEBUG)
        debug_log.setFormatter(CustomFormatter(ignore_color=True))
        l.addHandler(screen)
        l.addHandler(debug_log)

        '''l.basicConfig(
            level=l.DEBUG,
            format="%(asctime)s [%(levelname)s]   \t%(message)s",
            handlers=[
                l.FileHandler("debug.log"),
                l.StreamHandler()
            ]
        )'''
    else:
        l.setLevel(logging.INFO)
        #log handlers
        screen = logging.StreamHandler()
        screen.setLevel(logging.INFO)
        screen.setFormatter(CustomFormatter())
        debug_log = logging.FileHandler('debug.log')
        debug_log.setLevel(logging.INFO)
        debug_log.setFormatter(CustomFormatter(ignore_color=True))
        l.addHandler(screen)
        l.addHandler(debug_log)

        '''l.basicConfig(
            level=l.INFO,
            format="%(asctime)s [%(levelname)s]   \t%(message)s",
            handlers=[
                l.FileHandler("debug.log"),
                l.StreamHandler()
            ]
        )'''

    temp = vars(args)
    query_filter_dict = {}
    for key in temp:
        if (key not in ('verbose', 'devices', 'query', 'netconn', 'rows', 'command', 'output', 'start', 'end', 'window')) and (temp[key] != None):
            query_filter_dict[key] = temp[key]
    
    # Table template configurations
    if (args.command == "investigate") and args.enriched_event_type :
        template_name = args.enriched_event_type.upper()
        export_template = TABLE_TEMPLATE[template_name]
        l.info(f'Chose the {template_name} template for the output file')

    else:
        export_template = TABLE_TEMPLATE['general_template']
        l.info(f'Chose the general_template for the output file')

    return args, query_filter_dict, export_template

def main():
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
    # ARGUMENT PARSER
    args, query_filter_dict, export_template = argument_parser(author='Stephen Hurd', version=0.3, date='04/03/2023')

    #LOGGING CONFIG

    # API connect
    api = api_connect('default')

    # MAIN LOGIC
    if(args.devices):
        download_devices(api=api,output_file=args.output)

    if(args.command == 'investigate'):
        try:
            rows_limit = args.rows
        except:
            rows_limit = 10000
        query = build_query(
            api=api,query_type='enriched_event',
            rows=rows_limit,
            start=args.start,
            end=args.end,
            window=args.window,
            kwargs=query_filter_dict
        )
        results = query.make_query()
        get_enriched_events(results,export_template=export_template,output_file=args.output, verbose=args.verbose)
        
    if(args.command == 'query_processes'):
        l.error('This functionality has not been implemented yet. Please be patient while I work hard to get this function implemented properly.')
        exit()

if __name__ == "__main__":
    main()