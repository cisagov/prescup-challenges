#!/usr/bin/python3

import json
import requests
from bs4 import BeautifulSoup

class AutoBuy:

    baseUrl = 'http://wholesaler.us'
    loginUrl = baseUrl + '/login'
    defineProductUrl = baseUrl + '/admin/rest/define'
    addStockUrl = baseUrl + '/admin/rest/addStock/'

    headerPatch = { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
        'Referer': 'https://www.cmu.edu/' }

    username = 'user'
    password = 'password'

    session = None
    csrfToken = ''

    def __init__( self, username, password ):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update( self.headerPatch )# always work no matter what state the server is in
        self.login()

    def login( self ):
        loginPage = self.session.get( self.loginUrl )
        csrf = self.parseCsrf( loginPage.text )
        loginPayload = { 'username': self.username, 'password': self.password, '_csrf': csrf }
        loginProc = self.session.post( self.loginUrl, data = loginPayload )
        self.csrfToken = self.fetchCsrf()

    def parseCsrf( self, text ):
        soup = BeautifulSoup( text, 'html.parser' )
        return soup.find( 'input', { 'name':'_csrf' } )['value']

    def fetchCsrf( self ):
        r = self.session.get( self.baseUrl )
        soup = BeautifulSoup( r.text, 'html.parser' )
        return soup.find( 'meta', { 'name': '_csrf' } )['content']

    def checkout( self ):
        payload = { 'FSTAT': '039', '_csrf': self.csrfToken, 'payment': 'RepHold' }
        r = self.session.post( self.baseUrl + '/checkout', data = payload )
        return r.text

    def addToCart( self, items ):
        payload = { 'FSTAT': '039', 'csrfToken': self.csrfToken }
        idx = 1
        for item in items:
            payload['ID-'       + '{:05d}'.format(idx)] = item['id']
            payload['NAME-'     + '{:05d}'.format(idx)] = item['name']
            payload['PRICE-'    + '{:05d}'.format(idx)] = item['price']
            payload['QUANTITY-' + '{:05d}'.format(idx)] = item['quantity']
            idx = idx + 1
        r = self.session.post( self.baseUrl + '/rest/cart', json = payload )
        return r.text
