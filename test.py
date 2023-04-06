from cbc_sdk.rest_api import CBCloudAPI
from cbc_sdk.platform import Device, Process
from cbc_sdk.base import QueryBuilder
from cbc_sdk.endpoint_standard import EnrichedEvent, EnrichedEventFacet
from cbc_sdk.utils import convert_from_cb, convert_to_cb
import argparse

api = CBCloudAPI(profile='default')

def get_enriched_event_facet(api):
    '''
    Testing facet capabilities
    '''
    range = {'bucket_size': '+1HOUR','start': '2023-04-02T00:00:00Z','end': '2023-04-02T04:00:00Z','field': 'device_timestamp'}
    fields = ['process_name','process_username','device_name']
    facet_query = api.select(EnrichedEventFacet).where("process_name: *").add_range(range)
    facet_query.add_facet_field(fields)
    facet_results = facet_query.results

    print(facet_results)    

    return facet_results

facet_results = get_enriched_event_facet(api=api)

dict1 = facet_results.terms[0]['values']
term1 = facet_results.terms[0]['field']

dict2 = facet_results.terms[1]['values']
term2 = facet_results.terms[1]['field']

device_names = []
for entry in dict1:
    device_names.append(entry['name'])
print(device_names)
print(len(device_names))

# set the time range like this (on device_timestamp)
q.set_time_range(start='2023-04-03T00:00:00Z',end='2023-04-03T01:00:00Z')
# window overrides the time_range
q.set_time_range(window='-3[y,w,d,h,m,s]')

#print(f'{term1}\tTotal: {dict1[0]["total"]}\tDevice_Name:{dict1[0]["name"]} \n{term2}\tTotal: {dict2[0]["total"]}\tProcess_Name: {dict2[0]["name"]}')