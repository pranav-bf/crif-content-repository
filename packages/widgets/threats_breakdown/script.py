# sample name -> widgets/accounts_compromised/script.py
from datetime import datetime
import time
from datetime import datetime, timedelta


# this to return default widget config



def configure():
    return {
        "searchable": False,
        "datepicker":True,
        "properties": {"type": "column","onclick":"not_open_offcanvaspanel"},
        "dimension": {"x": 0, "y": 18, "width": 12, "height": 3}
    }


# this to return query to be used for rendering widget and its parameters
def query():
    # converting time into seconds
    starttime =parameters.get("starttime")/1000
    endtime = parameters.get("endtime")/1000

    endtime = datetime.utcfromtimestamp(endtime)
    starttime = datetime.utcfromtimestamp(starttime)

    delta = endtime - starttime
    daysBetween = delta.days


    # timerange = 'HH24' if 0 <= daysBetween <= 7 else 'DD Mon' if 7 < daysBetween <= 90 else 'YYYY-MM' if 90 < daysBetween <= 365 else 'YYYY'
    timerange = None

    if 0 <= daysBetween <= 2:
        # hours
        timerange='YYYY-MM-DD HH24'
     

    elif 2 < daysBetween <= 90:
        # days
 
        timerange='YYYY-MM-DD'
        
    elif 90 < daysBetween <= 365:
        # months
        timerange='YYYY-MM'

    elif daysBetween > 365:
        # years
        timerange='YYYY'
   
    return {
        "query": "SELECT distinct detectioncriticality as detectioncriticality ,COUNT(detectionid) AS count, TO_CHAR(to_timestamp(scoretimestamp/1000), '" + timerange + "') AS xaxis FROM entityscoring GROUP BY detectioncriticality,xaxis order by xaxis DESC",
        "parameters": {},
    }



# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None


# this to return free text search query and its parameters
def search(freetext):
    return None


def sort():
    return None


# this to return return formated results to render a widget
def render(results):

    try:
        if not results or len(results) == 0:
            raise Exception("no results found")
        

        intialstarttime=parameters.get("starttime")
        intialendtime=parameters.get("endtime")

        

        starttime = intialstarttime/1000
        endtime = intialendtime/1000

        endtime = datetime.utcfromtimestamp(endtime)
        starttime = datetime.utcfromtimestamp(starttime)

        delta = endtime - starttime
        time_differnce = delta.days

        

        field=None
        timerange=None
        if 0 <= time_differnce <= 7:
        
            field = 'hours'
            timerange="%Y-%m-%d %H"


        elif 7 < time_differnce <= 90:
        
            field = 'days'
            timerange="%Y-%m-%d"

        elif 90 < time_differnce <= 365:

            field = 'months'
            timerange="%Y-%m"
        
        elif time_differnce > 365:
            field = 'years'
            timerange="%Y"


    
        refined_data=__required_time(results,intialstarttime,intialendtime,timerange,field) 
    
        
        distinct_xaxis_values = list(set(result["xaxis"] for result in refined_data))


        distinct_xaxis_array = sorted(distinct_xaxis_values)


        dict = {}

        for result in refined_data:
            list1 = dict.get(result.get('detectioncriticality'))
            if list1 is None :
                dict[result.get('detectioncriticality')] = [0] * len(distinct_xaxis_array)
            dict[result.get('detectioncriticality')][distinct_xaxis_array.index(result.get('xaxis'))]=result.get('count')

        finalResult = []
        for key in dict:
            newDict = {}
            if key is not None:
                newDict['name'] = key
                newDict['data'] = dict[key]
                finalResult.append(newDict)
        
        return {"result":{"categories":distinct_xaxis_array,"series":finalResult}}
    

    except Exception as e:
            raise RuntimeError(e)



def __time_list(starttime, endtime, time_range, field):
    
    try:
        time_list = []    
        current_time = datetime.fromtimestamp(starttime / 1000)  # Convert milliseconds to seconds
        end_time = datetime.fromtimestamp(endtime / 1000)        # Convert milliseconds to seconds

        while current_time <= end_time:
            time_list.append(current_time.strftime(time_range))
            if field == 'hours':
                current_time += timedelta(hours=1)
            elif field == 'days':
                current_time += timedelta(days=1)
            elif field == 'months':
                current_time = current_time.replace(day=1) + timedelta(days=32)  # Move to next month
                current_time = current_time.replace(day=1)  # Set to the first day of the month
            elif field == 'years':
                current_time = current_time.replace(year=current_time.year + 1, month=1, day=1)

        return time_list

    except Exception as e:
        raise RuntimeError(e)
    


def __required_time(results,starttime,endtime,time_range,field):
    date_map=__time_list(starttime,endtime,time_range,field)
    
    
    # Create a set of existing xaxis values from the results list
    existing_xaxis_values = set(item['xaxis'] for item in results)
    
    # Iterate over new_timelist and add missing xaxis values to results
    for new_time in date_map:
        if new_time not in existing_xaxis_values:
            results.append({"xaxis": new_time})
    return results
  