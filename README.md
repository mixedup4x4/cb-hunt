# cb-hunt
cb-hunt is a python project to integrate with the Carbon Black API to perform threat hunts at scale. 

usage: python3.exe hunt.py [-h] [-v] [-d] [-o OUTPUT] {investigate} ...

hunt.py allows an analyst to retrieve a wealth of information from the Carbon Black Cloud (CBC) API. This tool currently supports the following functionality:
    - A full export of all devices in the tennant
    - Customized enriched event queries (this is the "investigate" tab in the console GUI)

**  Make sure that you have the proper authentication file in place, as found in https://carbon-black-cloud-python-sdk.readthedocs.io/en/latest/authentication/.
    Currently, this program only supports file based authenticaiton.
**  This may seem extremly slow compared to exporting searches from the console GUI. This is because this tool provides extended information that is not available
    in the exports from the GUI. In my opinion, these details are very desirable in a Threat Hunting scenario, but maybe not in a Incident Response scenario. If
    you are in a rush and don't need specific details, then I would reccomend using the GUI untill I implement simplified functionaility to this script.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Turn on verbose logging. Enables debug messages. This can be very noisy
  -d, --devices         Export all of the devices to a csv file
  -o OUTPUT, --output OUTPUT
                        File name or path to store the results in

subcommands:
  The following subcommands are supported:

  {investigate}         Use these sub commands to start dialing in your query
    investigate         Start building an enriched event query with supported filters. Wildcards are supported.

Author: Stephen Hurd    Version: 0.3    Date: 04/03/2023

        Example usage:
            python3.exe hunt.py -d -o devices.csv
            python3.exe hunt.py -o [output.csv] investigate --device_name [hostname] --enriched_event_type [type] --ipaddr [IP]
            
usage: python3.exe hunt.py investigate [-h] [--device_name DEVICE_NAME [DEVICE_NAME ...]] [--cmdline CMDLINE [CMDLINE ...]] [--process_name PROCESS_NAME [PROCESS_NAME ...]] [--ipaddr IPADDR [IPADDR ...]]       
                                       [--domain_name DOMAIN_NAME [DOMAIN_NAME ...]] [--enriched_event_type ENRICHED_EVENT_TYPE] [--event_type EVENT_TYPE] [--username USERNAME [USERNAME ...]] [--rows ROWS]     
                                       [--start START] [--end END] [--window WINDOW]

options:
  -h, --help            show this help message and exit
  --device_name DEVICE_NAME [DEVICE_NAME ...]
                        Filter by device name
  --cmdline CMDLINE [CMDLINE ...]
                        Filter by command line
  --process_name PROCESS_NAME [PROCESS_NAME ...]
                        Filter by process name
  --ipaddr IPADDR [IPADDR ...]
                        Filter by IP address
  --domain_name DOMAIN_NAME [DOMAIN_NAME ...]
                        Filter by domain name
  --enriched_event_type ENRICHED_EVENT_TYPE
                        Filter by enriched event type
  --event_type EVENT_TYPE
                        Filter by event type
  --username USERNAME [USERNAME ...]
                        Filter by username
  --rows ROWS           Number of rows to get. Default is the maximum - 10000
  --start START         Timestamp (UTC) to start searching at in ISO 8601 format
  --end END             Timestamp (UTC) to end searching in ISO 8601 format
  --window WINDOW       Relative time in the format of -1[y,d,h,m,s]. Default is -7d (days)
