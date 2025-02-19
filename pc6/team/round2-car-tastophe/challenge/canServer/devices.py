import datetime
import struct
import subprocess
import can
import random
import time as myTime  # Need to do this to avoid conflicting with the 'time' object in apscheduler
import logging
# from can.interfaces.udp_multicast import UdpMulticastBus
# from apscheduler.schedulers.blocking import BlockingScheduler

slowdown = 1 # Slows all generic devices down by this amount. 1 for normal, 100 is 100x slower
logging.info(f"Using a slowdown of {slowdown}x")

# Managed outside as needs to be modified by a listener
dynamicStatus = {
    "on": False,
    "power": 0,
    "displayOn1": 0x08,
    "displayOn2": 0x80,
    "userFanSpeed": 0,
    "brakesHalted": False
}

class vehicle_stats:
    speed = 60  # Modified by motor_rpm device
    horsepower = 170  # Modified by power_vcm device
    motor_amps = (0, 0)  # Modified by power_vcm device
    turnLight = 0x06

def combine(a, b, x):
    '''Combines bytes a and b into one number by add the last x bits of b (result is a number with 8+x bits).'''
    #First, shift bits to keep to the left (if b is 0b11001111 and x is 2, get 0b1100111100)
    temp = b << x
    # Mask off 8 bits (0b1100111100 & 0xff00 is 0b1100000000)
    temp = temp & 0xff00
    return a | temp  # Now if a is 2, final result is 0b1100000010 or 770, a 10-bit number

def split(a, x):
    '''Takes a 1 byte + x bits int and splits into an 8 bit and an x-length (padded by 8-x 0's)'''
    return (0x00ff & a, (a & 0xff00) >> x)

def getBits(a, x, y):
    '''Retrieves bits x-y from a. Like 0b11100010 , 5, 7, would return 0b111 or 7'''
    temp = a >> x  # Get rid of any extra bits at the start
    return temp & (0b11111111 >> (8-(y-x+1)))  # Get rid of any bits at the end
    
def setBit(a, x):
    '''Turns on the bit in a at location x. 0b11101111, 4 would return 0b11111111'''
    return a | (0b1 << x)

def unsetBit(a, x):
    '''Turns off the bit in a at location x. 0b11111111, 4 would return 0b11101111'''
    return a & (0xff ^ (0b1 << x))

def getTopoValue(name, default = "11deadbeef313373"):
        out = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.{name}'", shell=True, capture_output=True)
        val = out.stdout.decode('utf-8').strip()
        if 'no' in val or name in val or val == "":
            logging.warning(f"USING DEFAULT TOKEN VALUE for {name}!!!")
            return str(default)
        return str(val)

class malDev:
    '''Malicious device that sends a token message every few seconds'''
    
    def __init__(self, bus : can.BusABC, id : int = 0x12345678) -> None:
        self.messages = self.getToken()
        self.index = 0
        self.bus = bus
        self.interval = 5
        self.id = id
        self.name = "Rogue Device"

    def getToken(self):
        val = getTopoValue("tokenRead", "11deadbeef313373")
        return [int(val[i:i+2], base=16) for i in range(0, len(val), 2)]

    def sendMessage(self):
        message = can.Message(arbitration_id=self.id, data=self.messages)
        self.bus.send(message)
        
class secretMessage():        
    def __init__(self, bus : can.BusABC) -> None:
        secret_ids = [0x342, 0x509, 0x55a, 0x5f8, 0x5f9, 0x604, 0x682]
        i = random.randint(0, len(secret_ids) - 1)
        self.messages = self.getToken()
        self.index = 0
        self.bus = bus
        self.interval = 30 + len(self.messages)  # 30 seconds + 1 sec for each byte to broadcast
        self.id = secret_ids[i]
        logging.info(f"Secret message is transmitting in id 0x{self.id:x}")
        self.name = "Secret"

    def getToken(self):
        val = getTopoValue("tokenSecret", "11deadbeef313373")
        x = [int(val[i:i+2], base=16) for i in range(0, len(val), 2)]
        return x
    
    # Believe this is no longer used with new time technique
    def popMessage(self):
        '''Returns and increments the message queue'''
        x= self.messages[self.index]
        self.index = (self.index + 1) % len(self.messages)        

        return x

    def sendMessage(self):
        # Send 1 byte out every second
        for i in range(0, len(self.messages)):
            message = can.Message(arbitration_id=self.id, data=[self.messages[i]])
            self.bus.send(message)
            myTime.sleep(1)

class GenericCanDevice:
    '''Generic device, those that don't need to do anything special'''
    def __init__(self, bus : can.BusABC, id : int, interval : float = 5, name : str = "") -> None:
        self.bus = bus
        self.id = id
        self.index = 0
        self.interval = interval * slowdown
        self.name = name  # For debugging purposes
        self.bytes = [0]

    def update(self):
        pass
   
    def sendMessage(self):
        '''Send a predifined message or random value'''
        self.update()
        message = can.Message(arbitration_id=self.id, data=self.bytes)
        self.bus.send(message)

class Brakes(GenericCanDevice):
    '''Emulating brakes'''
    # self.id = 0x1ca
    # self.length = 4
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x1ca, .01, name="Brakes")
        self.brake = 100
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]

    def update(self):
        x = random.randint(-2, 2)
        y = random.randint(0, 100)
        regen = random.randint(0x40, 0xc0)
        if y < 95:
            x = 0  # Brakes shouldn't change that much
            regen = self.bytes[5]
        
        self.brake += x
        # Keep it in a healthy range
        if self.brake < 80:
            self.brake = 80
        elif self.brake > 120:
            self.brake = 120

        # Regen braking should be between 0x40 and 0xc0
        self.bytes = [self.brake, self.brake, self.brake, self.brake, 0x0, regen, 0x0, 0x0 ]  # All four brakes should be the same value

class Steering(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x002, .01, name="Steering")
        self.bytes = [0, 0, 0, 0x07, 0]
    
    def update(self):
        angle = combine(self.bytes[0], self.bytes[1], 8)
        angleValue = struct.unpack('<h', angle.to_bytes(2, 'little'))[0]
        change = random.randint(-2, 2) * slowdown  # Change faster if messages slow down 
        newAngleValue = angleValue + change
        
        if newAngleValue < -3600 or newAngleValue > 3600:
            newAngleValue = angleValue
        temp = struct.pack('<h', newAngleValue)  # Need this to properly get signed number
        b1 = int(temp[0])
        b2 = int(temp[1])       

        b3 = change if change > 0 else -1*change
        # print(f"Setting steering to {newAngleValue} from {angleValue}. Change is {change}.")
        self.bytes = [b1, b2, b3, 0x07, random.randint(0, 0xff)]
        
class unknown_02a(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x02a, .1, name="Unknown_02a")
        self.bytes = [0, 0, 0]

class abs(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x130, .01, name="abs")
        self.bytes = [0, 0, 0]

class vcm(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x174, .01, name="vcm")
        self.bytes = [0, 0, 0, 0xbb, 0x0f, 0, 0, 0]
        
class motor_rpm(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x176, .01, name="motor_rpm")
        temp1 = struct.pack('<h', 828)
        temp2 = struct.pack('<h', 6593)
        self.bytes = [int(temp1[0]), int(temp1[1]), int(temp2[0]), int(temp2[1]), 0, 0, 0x0f]
    
    def update(self):
        # speed1 = combine(self.bytes[0], self.bytes[1], 8)
        # speed1Value = struct.unpack('<h', speed1.to_bytes(2, 'little'))[0] * 0.0725
        speed1Value = vehicle_stats.speed
        
        change = random.randint(-1, 1) * slowdown  # Change faster if messages slow down 
        y = random.randint(0, 100)
        if y < 98:
            change = 0  # Don't change that much
        vehicle_stats.speed = speed1Value + change

        newspeed1Value = (speed1Value + change) * 0.0725
        newspeed2Value = (speed1Value + change) * 0.0091
        
        if (speed1Value < 10 and change < 0) or (speed1Value > 70 and change > 0):
            newspeed1Value = speed1Value * 0.0725
            newspeed2Value = speed1Value * 0.0091
            
        temp = struct.pack('<h', int(newspeed1Value))
        b1 = int(temp[0])
        b2 = int(temp[1]) 
        temp = struct.pack('<h', int(newspeed2Value)) 
        b3 = int(temp[0])
        b4 = int(temp[1])      

        self.bytes = [b1, b2, b3, b4, 0, 0, 0x0f]

class power_vcm(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x180, .01, name="power_vcm")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]
        self.decay = 1.0
    
    def update(self):
        hp = vehicle_stats.horsepower
        
        change = random.randint(-1, 1) * slowdown  # Change faster if messages slow down 
        y = random.randint(0, 100)
        if y < 98:
            change = 0  # Don't change that much
        else:
            self.decay = self.decay - 0.001

        newhp = (hp + change)
        
        if (hp < 147 and change < 0) or (hp > 214 and change > 0):
            newhp = hp
        
        vehicle_stats.horsepower = newhp
        
        motor = (newhp * 0.75 * 176.23) / 30

        temp = struct.pack('<h', int(motor))
        self.bytes[2] = int(temp[0])
        self.bytes[3] = int(temp[1])
        
        vehicle_stats.motor_amps = (temp[0], temp[1])
        
        temp = struct.pack('<h', int(motor * self.decay))
        self.bytes[4] = int(temp[0])
        self.bytes[5] = int(temp[1])

        
class power_vcm(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x1cb, .01, name="power_vcm")
        self.bytes = [0, 0, 0, 0, 0, 0, 0]
    
    def update(self):
        targetRegenRaw = combine(self.bytes[0], self.bytes[1], 3)
        targetRegen = struct.unpack('<h', targetRegenRaw.to_bytes(2, 'little'))[0]
        
        change = random.randint(-1, 1) * slowdown  # Change faster if messages slow down 
        y = random.randint(0, 100)
        if y < 98:
            change = 0  # Don't change that much

        newtargetRegen = (targetRegen + change) * 0.0725
        newtargetBraking = (targetRegen + change) * 0.0091
        
        if (targetRegen < 10 and change < 0) or (targetRegen > 70 and change > 0):
            newtargetRegen = targetRegen * 0.0725
            newtargetBraking = targetRegen * 0.0091
            
        temp = struct.pack('<h', int(newtargetRegen))
        b1 = int(temp[0])
        b2 = int(temp[1]) 
        temp = struct.pack('<h', int(newtargetBraking)) 
        b3 = int(temp[0])
        b4 = int(temp[1])      

        self.bytes = [b1, b2, b3, b4, 0, 0, 0x0f]

class unknown_1d5(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x1d5, .01, name="Unknown_1d5")
        self.bytes = [0, 0, 0, 0, 0]
        
    def update(self):
        self.bytes = [vehicle_stats.motor_amps[0], vehicle_stats.motor_amps[1], 0, 0, 0]

class unknown_1f9(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x1f9, .01, name="Unknown_1f9")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]

class unknown_215(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x215, .02, name="Unknown_215")
        self.bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]

class prox(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x216, .02, name="prox")
        self.bytes = [0, 0]

class unknown_245(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x245, .02, name="Unknown_245")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]
        self.four = 0

    def update(self):
        y = random.randint(0, 100)
        if y > 90:
            self.four = (self.four + 1) % 256
            self.bytes = [0, 0, 0, 0, self.four, 0, 0, 0]

class cluster_display(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x260, .02, name="cluster_display")
        self.bytes = [0x50, 0, 0x19, 0x00]
        self.round = [0x0, 0x6, 0xc, 0x12, 0x18]
        self.index = 0
        
    def update(self):
        self.bytes[1] = self.round[self.index]
        self.index = (self.index + 1) % len(self.round)

class eyebrow(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x280, .02, name="eyebrow")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]
        
    def update(self):
        value = vehicle_stats.speed * .0062     
        self.bytes[4], self.bytes[5]  = struct.pack('<h', int(value)) 

class frontWheels(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x284, .02, name="frontwheels")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]

        
    def update(self):
        tire_speed_byte = (((63360 / 8) * vehicle_stats.speed) / 60) * .0118   
        self.bytes[0], self.bytes[1] = struct.pack('<h', int(tire_speed_byte)) 
        self.bytes[2], self.bytes[3] = (self.bytes[0], self.bytes[1])

class backWheels(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x285, .02, name="backwheels")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]
        
    def update(self):
        tire_speed_byte = (((63360 / 8) * vehicle_stats.speed) / 60) * .0118   
        self.bytes[0], self.bytes[1] = struct.pack('<h', int(tire_speed_byte)) 
        self.bytes[2], self.bytes[3] = (self.bytes[0], self.bytes[1]) 

class unknown_292(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x292, .02, name="unknown_292")
        self.bytes = [0, 0, 0, 0x7f, 0, 0, 0, 0]
        
    def update(self):
        val = (vehicle_stats.horsepower * 0.75 * 176.23) / 30
        self.bytes[6], self.bytes[7] = struct.pack('<h', int(val * 5))

class unknown_2de(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x2de, .01, name="unknown_2de")
        self.bytes = [0, 0, 0, 0, 0, 0, 0x03, 0xca]

class steeringForce(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x300, .02, name="steeringForce")
        self.bytes = [50]

class unknown_351(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x351, .1, name="unknown_351")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]

class unknown_354(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x354, .04, name="unknown_354")
        self.bytes = [0, 0, 0, 0, 0x40, 0, 0, 0]
    
    def update(self):
        self.bytes[0], self.bytes[1] = struct.pack('<h', int(vehicle_stats.speed))

class unknown_355(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x355, .04, name="unknown_355")
        self.bytes = [0, 0, 0, 0, 0x20, 0, 0x60]
    
    def update(self):
        self.bytes[0], self.bytes[1] = struct.pack('<h', int(vehicle_stats.speed * 1.609))
        self.bytes[2], self.bytes[3] = struct.pack('<h', int(vehicle_stats.speed))  

class bodyControl(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x358, .1, name="bodyControl")
        self.bytes = [0, 0b10000000, 0, 0, 0, 0, 0, 0]
        self.count = 0  # Leave signals on for 20 messages (2 second at normal speed)

    def update(self):
        r = random.randint(0,100)

        if self.bytes[2] != 0:
            if self.count == 20:
                self.count = 0
                self.bytes[2] = 0
                vehicle_stats.turnLight = 0x06  # Off
                return
            self.count += 1
            return
            
        if r >= 80 and r < 90:
            self.bytes[2] = setBit(0, 3)  # Right turn
            vehicle_stats.turnLight = 0x26
        elif r >= 90:
            self.bytes[2] = setBit(0, 2)  # Left turn
            vehicle_stats.turnLight = 0x46

class unknown_35d(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x35d, .1, name="unknown_35d")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]

class tpms(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x385, .1, name="tpms")
        self.bytes = [0, 0, 32, 31, 32, 30, 0b11110000, 0]

class prndl(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x421, .06, name="prndl")
        self.bytes = [0x20]  # Drive

class ACCompressor(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x50a, .1, name="ACCompressor")
        self.bytes = [0, 0, 0, 0, 0, 0]

class unknown_50d(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x50d, .1, name="unknown_50d")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]

class climatePower(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x510, .1, name="climatePower")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0x86]

class climateSet(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x54a, .1, name="climateSet")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0x79]

class climateDisplay(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x54b, .1, name="climateDisplay")
        self.bytes = [0, 0x08, 0x80, 0, 0, 0, 0, 0]

class unknown_551(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x551, .1, name="unknown_551")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]

class parkingBrake(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x58a, .1, name="parkingBrake")
        self.bytes = [0, 0, 0xfd] 

class batteryTemp(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5b3, .5, name="batteryTemp")
        self.bytes = [92, 100, 0, 0, 0, 0, 0b11111000, 100] 

class unknown_5c0(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5c0, .5, name="unknown_5c0")
        self.bytes = [0, 0, 0, 0b10011100, 0, 0, 0, 0]

class odometer(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5c5, .1, name="odometer")
        self.bytes = [0, 0xf0, 0x55, 0, 0, 0x0c, 0, 0]

class unknown_5e3(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5e3, .5, name="unknown_5e3")
        self.bytes = [0, 0, 0, 0]

class unknown_5e4(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5e4, .1, name="unknown_5e4")
        self.bytes = [0, 0, 0]


class monthDay(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5fa, .5, name="monthday")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]
        
    def update(self):
        n = datetime.datetime.now()
        self.bytes[2] = int(n.strftime("%d"))
        self.bytes[5] = int(n.strftime("%m"))
        
class unknown_5fb(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5fb, .5, name="unknown_5fb")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]
        
class time(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x5fc, .5, name="time")
        self.bytes = [0, 0, 0, 0, 0, 0, 0, 0]
        
    def update(self):
        n = datetime.datetime.now()
        self.bytes[0] = int(n.strftime("%H"))
        self.bytes[1] = int(n.strftime("%S"))
        self.bytes[2] = int(n.strftime("%M"))

class lights(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x60d, .1, name="lights")
        self.bytes = [0, 0, 0x06, 0, 0, 0, 0, 0]
        
    def update(self):
        self.bytes[2] = vehicle_stats.turnLight
        if vehicle_stats.turnLight == 0x26:
            # Right turn
            self.bytes[1] = 0b01000110
        elif vehicle_stats.turnLight == 0x46:
            # Right turn
            self.bytes[1] = 0b00100110

class headlights(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x625, .1, name="headlights")
        self.bytes = [0, 0x60, 0, 0, 0, 0]

class unknown_6f6(GenericCanDevice):
    def __init__(self, bus : can.BusABC)  -> None:
        super().__init__(bus, 0x6f6, .1, name="unknown_6f6")
        self.bytes = [0, 0, 0]