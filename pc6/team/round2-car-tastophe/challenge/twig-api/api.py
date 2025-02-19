from flask import Flask, jsonify, request
from datetime import datetime, timedelta

app = Flask(__name__)

d = datetime.today() - timedelta(days=1)
d = d - timedelta(days=1)
d = d.replace(hour=21, minute=2, second=32)

exampleUser = "TotallyNotAFed"
exampleDCMID = "614427018836"
exampleVIN = "R0MHBBXF3P50" + "12345"
exampleAuthToken = "BDEBMYVTAOVWKIJEJAVNBIWHMOUWJOIMXFGAMDNEVKKCQFVYNTDMSJVTWTKRVARCHGOZGGOVJNBBQH"  # Not used as login not used

targetVIN = "R0MHBBXF3P50" + "69X37"

exampleACState = {"on": False, "battery": False, "opTime": datetime.now().strftime("%b %d, %Y %I:%M %p")}
targetACState = {"on": False, "battery": True, "opTime": datetime.now().strftime("%b %d, %Y %I:%M %p")}

exampleLogin = {
    "status": 200,
    "message": "success",
    "sessionId": "21117204-9558-1595-9788-6437410550",
    "VehicleInfoList": {
        "VehicleInfo": [
            {
                "charger20066": "false",
                "nickname": "TWIG",
                "telematicsEnabled": "true",
                "vin": exampleVIN
            }
        ]
    },
    "vehicle": {
        "profile": {
            "vin": exampleVIN,
            "gdcUserId": exampleUser,
            "encAuthToken": exampleAuthToken,
            "dcmId": exampleDCMID,
            "status": "ACCEPTED",
            "statusDate": d.replace(minute=0).strftime("%b %d, %Y %I:%M %p")
        }
    },
    "EncAuthToken": exampleAuthToken,
    "CustomerInfo": {
        "UserId": exampleUser,
        "Language": "en-US",
        "Timezone": "America\/New_York",
        "RegionCode": "US",
        "OwnerId": "8338032814",
        "Nickname": exampleUser,
        "Country": "US",
        "VehicleImage": "\/content\/language\/default\/images\/img\/ph_car.jpg",
        "UserVehicleBoundDurationSec": "999971200",
        "VehicleInfo": {
            "VIN": exampleVIN,
            "DCMID": exampleDCMID,
        }
    },
    "UserInfoRevisionNo": "1"
}

targetBattery = {
    'status': 200,
    'message': "success",
    'BatteryStatusRecords': {
        'OperationResult': "STOP",
        "OperationDateAndTime": d.strftime("%b %d,%Y %H:%M"),
        'BatteryStatus': {
            'BatteryChargingStatus': "NOT_CHARGING",
            'BatteryCapacity': "12",
            'BatteryRemainingAmount': '11',
            'BatteryRemainingAmountWH': '',
            'BatteryRemainingAmountkWH': ''
        },
        'PluginState': 'NOT_CONNECTED',
        'TimeRequiredToFull': {
            'HoursRequiredToFull': '2',
            'MinutesRequiredToFull': '13'
        }
    }
}

exampleBattery = {
    'status': 200,
    'message': "success",
    'BatteryStatusRecords': {
        'OperationResult': "START",
        "OperationDateAndTime": d.replace(hour=8, minute=32, second=1).strftime("%b %d,%Y %H:%M"),
        'BatteryStatus': {
            'BatteryChargingStatus': "CHARGED",
            'BatteryCapacity': "12",
            'BatteryRemainingAmount': '12',
            'BatteryRemainingAmountWH': '',
            'BatteryRemainingAmountkWH': ''
        },
        'PluginState': 'CONNECTED',
        'TimeRequiredToFull': {
            'HoursRequiredToFull': '0',
            'MinutesRequiredToFull': '0'
        }
    }
}

def ACStatus(state):
    return {
        "status":200,
        "message":"success",
        "RemoteACRecords":{
            "OperationResult":"START_BATTERY" if state["battery"] else "START",
            "OperationDateAndTime": state["opTime"],
            "RemoteACOperation": "START" if state["on"] else "STOP",
            "ACStartStopDateAndTime":  state["opTime"],
            "CruisingRangeAcOn":"103498.1" if state["battery"] else "107712.0" ,
            "CruisingRangeAcOff": "101866.1" if state["battery"] else "109344.0",
            "ACStartStopURL":"",
            "PluginState":"NOT_CONNECTED" if state["battery"] else "CONNECTED",
        },
        "OperationDateAndTime": state["opTime"]
    }

targetACChange = {
    "status": 200,
    "message": "success",
    "userID": "SuperSpy007",
    "VIN": targetVIN
}

exampleACChange = {
    "status": 200,
    "message": "success",
    "userID": exampleUser,
    "VIN": exampleVIN
}

badVIN = {
    'status': "-5000",
    'message': "Unregistered VIN",
    'ErrorCode': "-5000",
    'ErrorMessage': "Unregistered VIN"
}

badDCIM = {
    'status': "-5001",
    'message': "Invalid DCIM",
    'ErrorCode': "-5001",
    'ErrorMessage': "DCIM value expired or invalid"
}

exampleLocation = {
    "Location": {
        "Country": "US",
        "Home": "OUTSIDE",
        "LatitudeDeg": "38",
        "LatitudeMin": "53",
        "LatitudeMode": "NORTH",
        "LatitudeSec": "4007",
        "LocationType": "WGS84",
        "LongitudeDeg": "77",
        "LongitudeMin": "01",
        "LongitudeMode": "EAST",
        "LongitudeSec": "2821",
        "Position": "UNAVAILABLE"
    },
    "TargetDate": d.strftime("%Y/%m/%d %H:%M"),
    "lat": "38.89447",
    "lng": "-77.0245",
    "receivedDate": d.strftime("%Y/%m/%d %H:%M"),
    "responseFlag": "1",
    "resultCode": "1",
    "status": 200,
    "timeStamp": d.strftime("%Y/%m/%d %H:%M")
}

targetLocation = {
    "Location": {
        "Country": "US",
        "Home": "1",
        "LatitudeDeg": "28",
        "LatitudeMin": "25",
        "LatitudeMode": "NORTH",
        "LatitudeSec": "0419",
        "LocationType": "WGS84",
        "LongitudeDeg": "81",
        "LongitudeMin": "34",
        "LongitudeMode": "EAST",
        "LongitudeSec": "3119",
        "Position": "UNAVAILABLE"
    },
    "TargetDate": d.strftime("%Y/%m/%d %H:%M"),
    "lat": "28.41783",
    "lng": "-81.57533",
    "receivedDate": d.strftime("%Y/%m/%d %H:%M"),
    "responseFlag": "1",
    "resultCode": "1",
    "status": 200,
    "timeStamp": d.strftime("%Y/%m/%d %H:%M")
}

def validate(args):
    vin = args.get('VIN')
    region = args.get('RegionCode')
    # To work for target, DCIM needs to be there, but should be blank like in the Leaf attack
    dcim = args.get('DCIM')
    
    if dcim != "":
        if dcim != exampleDCMID or vin != exampleVIN:
            return jsonify(badDCIM)

    if region != "US" or (vin != exampleVIN and vin != targetVIN):
        return jsonify(badVIN)

    return None


@app.route('/twig/gdc/BatteryStatusRecordsRequest', methods=['GET'])
def batteryStatus():
    vin = request.args.get("VIN")
    check = validate(request.args)
    if check is not None:
        return check

    if vin == targetVIN:
        return jsonify(targetBattery)
    return jsonify(exampleBattery)

@app.route('/twig/gdc/MyCarFinderRequest', methods=['GET'])
def carFinder():
    vin = request.args.get("VIN")
    check = validate(request.args)
    if check is not None:
        return check

    if vin == targetVIN:
        return jsonify(targetLocation)
    return jsonify(exampleLocation)

@app.route('/twig/gdc/RemoteACRecordsRequest', methods=['GET'])
def ACRecords():
    vin = request.args.get("VIN")
    check = validate(request.args)
    if check is not None:
        return check

    if vin == targetVIN:
        return jsonify(ACStatus(targetACState))
    return jsonify(ACStatus(exampleACState))

@app.route('/twig/gdc/ACRemoteRequest', methods=['GET'])
def ACOn():
    vin = request.args.get("VIN")
    check = validate(request.args)
    if check is not None:
        return check

    if vin == targetVIN:
        targetACState["on"] = True
        targetACState["opTime"] = datetime.now().strftime("%b %d, %Y %I:%M %p")
        return jsonify(targetACChange)
    exampleACState["on"] = True
    exampleACState["opTime"] = datetime.now().strftime("%b %d, %Y %I:%M %p")
    return jsonify(exampleACChange)


@app.route('/twig/gdc/ACRemoteOffRequest', methods=['GET'])
def ACOff():
    vin = request.args.get("VIN")
    check = validate(request.args)
    if check is not None:
        return check

    if vin == targetVIN:
        targetACState["on"] = False
        targetACState["opTime"] = datetime.now().strftime("%b %d, %Y %I:%M %p")
        return jsonify(targetACChange)
    exampleACState["on"] = False
    exampleACState["opTime"] = datetime.now().strftime("%b %d, %Y %I:%M %p")
    return jsonify(exampleACChange)


@app.route('/twig/gdc/PriceSimulatorDetailInfoRequests', methods=['GET'])
def priceSim():
    vin = request.args.get("VIN")
    check = validate(request.args)
    if check is not None:
        return check

    if vin == targetVIN:
        with open("targetTrips.json") as f:
            return app.response_class(
                response=f.read(),
                mimetype='application/json'
            )
    with open("exampleTrips.json") as f:
        return app.response_class(
            response=f.read(),
            mimetype='application/json'
        )


if __name__ == '__main__':
    app.run(debug=False)
