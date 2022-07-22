#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import time
import os
import sys
from selenium.common.exceptions import TimeoutException
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.expected_conditions import presence_of_element_located

creds = {}
creds['alex'] = 'helloworld'
creds['thor'] = 'thunderonthetundra'
creds['snake'] = 'namemeansnothingonthebattlefield'

username = os.popen( 'vmware-rpctool "info-get guestinfo.username"' ).read().strip()
password = creds[username]

print( "Victim Script - trigger participant XSS" )

with webdriver.Firefox( executable_path='/home/student/driver/geckodriver' ) as driver:
    driver.set_page_load_timeout( 4 )
    wait = WebDriverWait( driver, 10 )
    driver.get( "http://192.168.1.100/login" )
    driver.find_element( By.NAME, "username" ).send_keys( username )
    driver.find_element( By.NAME, "password" ).send_keys( password + Keys.RETURN )
    driver.get( "http://192.168.1.100/browse" )
    time.sleep( 2 )
    listings = driver.find_elements_by_css_selector( ".listingLink" )
    links = [ listing.get_attribute('href') for listing in listings ]
    for link in links:
        try:
            driver.get(link)
        except TimeoutException:
            print( 'timeout loading page ' + link )
        time.sleep( 4 )
        #driver.back()
        #time.sleep( 10 )


sys.exit( 1 ) #always exit with error so that bash can keep running the command with until

