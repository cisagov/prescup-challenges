from apscheduler.schedulers.blocking import BlockingScheduler
import requests

# Ping a twig-api endpoint every 5 seconds to allow user to discover them

host = "http://twig-api.merch.codes"
api = ['/twig/gdc/BatteryStatusRecordsRequest', '/twig/gdc/MyCarFinderRequest',
       "/twig/gdc/RemoteACRecordsRequest", '/twig/gdc/ACRemoteRequest', "/twig/gdc/RemoteACRecordsRequest",
       '/twig/gdc/ACRemoteOffRequest', '/twig/gdc/PriceSimulatorDetailInfoRequests'
       ]
query = "?DCIM=614427018836&VIN=R0MHBBXF3P5012345&RegionCode=US"
index = 0

def randomRequest():
    global index
    # Don't actually care about the response
    requests.get(host + api[index] + query)
    index = (index + 1) % len(api)

if __name__ == '__main__':

    sched = BlockingScheduler()
    sched.add_job(randomRequest, 'interval', seconds=5, max_instances=1, coalesce=True)
    try:
        sched.start() # Let sched run
    except KeyboardInterrupt:
        print('Ending server by interrupt!')
        sched.shutdown()