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

def run_query(api): #WIP
    process_query = api.select(Process).where(process_name="ir_agent.exe").and_(device_id="135536593")
    query_results = [proc for proc in process_query]
    """
        print(query_results[0])
        query_results[0]['device_name']
        query_results[0]['process_name']
        query_results[0]['process_hash']
        query_results[0]['process_username']
        query_results[0]['process_pid']
        query_results[0]['process_guid']

        Observation objects are easier to work with. Provide more info as well:
        observation = query_results[0].get_details()
        observation['process_username']

        Events are cool too. Run this method on a process object to retrieve them. 
        There is a lot of these.
        events = list(query_results[0].events())
        print(events[0])

        #converting strings to datetimes! Not necessarily needed, but cool. 
        print(convert_from_cb(query_results[0]['backend_timestamp']))
        #OR
        str(convert_from_cb(query_results[0]['backend_timestamp']))

        #Validate a process query first! #needs the following format.
        api.validate_process_query("process_name:chrome.exe") #returns true if valid

    """

def get_netconn_events(api): #WIP
    """
    Function that will retrieve all NETWORK events for a specified process
    export events to a csv
    """
    query = api.select(EnrichedEvent).where(enriched_event_type="NETWORK").set_rows(10000)
    try:
        #get the detailed output in an asynchronous fashion 
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
        with open('netconn.csv', 'w', newline='',encoding='utf-8') as csvfile:
            #Headers
            fields = [ #need to convert ingress time
                'backend_timestamp','ingress_time','device_name',
                'device_external_ip','event_network_local_ipv4','netconn_local_port','event_network_remote_ipv4','event_network_remote_port','event_network_inbound',
                'event_network_protocol','netconn_domain','netconn_location','netconn_actions',
                'process_name','process_start_time','process_cmdline','process_username','process_effective_reputation','process_pid','process_guid','process_sha256',
                'parent_name','parent_pid','parent_hash','parent_reputation',
                'ttp','device_id','event_id','event_description'
            ]
            
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
                            #normalizing dates
                            if field == "ingress_time":
                                value = int(str(value)[:-3])
                                value = datetime.fromtimestamp(value).isoformat(sep=" ",timespec='seconds')
                            
                            if (field == "backend_timestamp") or (field == "process_start_time"):
                                value = convert_from_cb(value).replace(tzinfo=None).isoformat(sep=" ",timespec='seconds')

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

    
def main():
    #ARGUMENT PARSER
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
    #parser.add_argument('-v', '--verbose', required=False, action=, help='')

    args = parser.parse_args()
    #LOGGING CONFIGURATION
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

    if(args.query):
        run_query(api)

    if(args.netconn):
        get_netconn_events(api)
        
if __name__ == "__main__":
    main()