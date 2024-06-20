#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import requests, random, time, json, datetime

def sensor_update():
	while True:
		for x in range(1,10):
			with open("/home/user/Desktop/script_log.txt","a+") as f:
				## generate key
				ran = random.randint(100,5000)
				key_val = ran * 7
				## get sensor into
				search = {
					"key": key_val,
					"search" :{
						"action": "search",
						"id":str(x)
					}
				}
				out1 = ''
				cur_time =  datetime.datetime.today().strftime('%M:%H, %m-%d-%Y')
				try:
					out1 = requests.post("http://10.7.7.7:9832", json=search, headers={"Content-Type":"application/json"}, timeout=1)
				except Exception as e:
					f.write(f'{cur_time} -- ERROR:\t' + str(e) + '\n')
				else:
					f.write(f'{cur_time} -- ' + out1.text + '\n')
					
				if (out1 == ''):
					time.sleep(3)
					f.write(f'{cur_time} -- No data in request. Verify sensor-api is up and returning response.')
					continue
				elif ('offline' in out1.text):
					time.sleep(3)
					f.write(f'{cur_time} -- server{x} offline')
					continue
				time.sleep(3)
				
				### update sensors
				chk = json.loads(out1.text)
				if x % 2 == 0:
					continue
					
				cur_time =  datetime.datetime.today().strftime('%M:%H, %m-%d-%Y')
				update = {
					"key": key_val,
					"search":{
						"action":"update",
						"id":str(x),
						"temp":"50"
					}
				}
				try:
					out2 = requests.post("http://10.7.7.7:9832", json=update, headers={"Content-Type":"application/json"}, timeout=1)
				except Exception as e:
					time.sleep(3)
					f.write(f'{cur_time} -- ERROR:\t' + str(e) + '\n')
				else:
					time.sleep(3)
					f.write(f'{cur_time} -- ' + out2.text + '\n')
				time.sleep(3)
	
if __name__ == '__main__':
	sensor_update()
