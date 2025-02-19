import datetime
import json
import random

def iterMonth():
    today = datetime.datetime.today().replace(hour=0, minute=0, second=0)
    start_of_month = datetime.datetime(today.year, today.month, 1, 0, 0, 0)
    
    
    if today.day <= 4:  # Start of month, use last month
        if today.month == 1:
            start_of_month = datetime.datetime(today.year - 1, 12, 1, 0, 0, 0)  # Dec last year if jan
            today = datetime.datetime(today.year, 1, 1, 0, 0, 0)
        else:
            start_of_month = datetime.datetime(today.year, today.month - 1, 1, 0, 0, 0)  # Previous month if not jan
            today = datetime.datetime(today.year, today.month, 1, 0, 0, 0)
        

    while start_of_month < today:
        yield start_of_month
        start_of_month += datetime.timedelta(days=1)

def random_time():
  """Generates a random time between 00:00:00 and 23:59:59."""

  random_seconds = random.randint(0, 86399)  # 86400 seconds in a day
  return datetime.timedelta(seconds=random_seconds)


def makeTrip(id, date : datetime.datetime):
    # Random numbers that seem realistic at a glance by keeping rough scales
    tripLength = random.randint(500, 20000)
    mileage = random.randint(1, 4) + random.random()
    powerMotor = tripLength / mileage
    powerMinus = tripLength / (mileage + 1 + random.random())
    powerTotal = powerMotor - powerMinus
    co2 = int(tripLength / 5000)
    
    date.replace(microsecond=0)  # Make sure this is not set
    return ({  
        "TripId": str(id),
        "PowerConsumptTotal": f"{powerTotal:.2f}",
        "PowerConsumptMotor": f"{powerMotor:.2f}",
        "PowerConsumptMinus": f"{powerMinus:.2f}",
        "TravelDistance": str(tripLength),
        "ElectricMileage": f"{mileage:.1f}",
        "C02Reduction": str(co2),
        "MapDisplayFlag": "NONACTIVE",
        "GpsDatetime": date.isoformat()
    }, (powerTotal, powerMotor, powerMinus, tripLength, mileage, co2))

def generateTrips(randMin=1, randMax=5, stopEarly=-1):
    trips = []
    total = 0
    motor = 0
    minus = 0
    totalTravel = 0
    mileage = 0
    co2 = 0

    for day in iterMonth():
        if stopEarly == 0:
            break
        elif stopEarly != -1:
            stopEarly -= 1        

        numTrips = random.randint(randMin, randMax)
        times = []
        for i in range(0, numTrips):
            times.append(day + random_time()) 
        times = sorted(times)
        for t in times:
            x = makeTrip(len(trips) + 1, t)
            trips.append(x[0])
            total += x[1][0]
            motor += x[1][1]
            minus += x[1][2]
            totalTravel += x[1][3]
            mileage += x[1][4]
            co2 += x[1][5]
    total = total / 1000
    motor = motor / 1000
    minus = minus / 1000

    output = {
        "status": 200,
        "message": "success",
        "PriceSimulatorDetailInfoResponsePersonalData": {
            "TargetMonth": day.strftime("%Y%m"),
            "TotalPowerConsumptTotal": f"{total:.5f}",
            "TotalPowerConsumptMotor": f"{motor:.5f}",
            "TotalPowerConsumptMinus": f"{minus:.5f}",
            "ElectricPrice": "0.1",
            "ElectricBill": f"{total/10:.6f}",
            "ElectricCostScale": "miles/kWh",
            "MainRateFlg": "COUNTRY",
            "ExistFlg": "EXIST",
            "PriceSimulatorDetailInfoDateList": trips,
            "PriceSimulatorTotalInfo": {
                "TotalNumberOfTrips": str(len(trips)),
                "TotalPowerConsumptTotal": f"{total:.5f}",
                "TotalPowerConsumptMotor": f"{motor:.5f}",
                "TotalPowerConsumptMinus": f"{minus:.5f}",
                "TotalTravelDistance": f"{totalTravel}",
                "TotalElectricMileage": f"{(mileage/len(trips)) / 1000:.4f}",  
                "TotalC02Reductiont": f"{co2}"
            },
            "DisplayMonth": day.strftime("%b/%Y"),
        }
    }

    return output

with open("targetTrips.json", "w") as f:
    json.dump(generateTrips(), f)
    
with open("exampleTrips.json", "w") as f:
    json.dump(generateTrips(1, 2, 2), f)  # Small amount (2-4) of data for example
