#!./python3

import json
import requests
from bs4 import BeautifulSoup

class AutoBuy:

    baseUrl = 'http://wholesaler.us'
    loginUrl = baseUrl + '/login'
    defineProductUrl = baseUrl + '/admin/rest/define'
    addStockUrl = baseUrl + '/admin/rest/addStock/'

    headerPatch = { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
        #'Host': 'www.rsrgroup.com',
        #'Origin': 'https://www.rsrgroup.com/',
        'Referer': 'https://www.rsrgroup.com/' }

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
        #print( 'Logging in...' )
        loginPage = self.session.get( self.loginUrl )
        csrf = self.parseCsrf( loginPage.text )
        #print( 'CSRF :', csrf )
        loginPayload = { 'username': self.username, 'password': self.password, '_csrf': csrf }
        loginProc = self.session.post( self.loginUrl, data = loginPayload )
        #print( loginProc.text )
        #print( 'Logged in.' )
        self.csrfToken = self.fetchCsrf()

    def createItem( self, name, cost, price, description ):
        prod = self.session.post( self.defineProductUrl, json = { 'name': name, 'price': price, 'cost':cost, 'description': description } )
        return json.loads( prod.text )

    def addStock( self, product, quantity ):
        prod = self.session.post( self.addStockUrl + str( product['id'] ), json = { 'quantity': quantity } )
        return json.loads( prod.text )

    def setMode( self, mode ):
        prod = self.session.post( self.baseUrl + '/admin/rest/difficulty/' + mode )
        print( prod.request.headers )
        return prod.text

    def junk( self ):
        r = self.session.post( self.baseUrl + '/rest/test', json = { 'alabaster': 'semencaster', 'it-0001': 'what' } )
        return r.text

    def fetchOrders( self, user ):
        r = self.session.get( self.baseUrl + '/admin/rest/orders/' + user )
        #print( r.request.headers )
        #print( r.request.url )
        return r.text

    def loadCart( self ):
        r = self.session.get( self.baseUrl + '/rest/cart' )
        return json.loads( r.text )

    def parseCsrf( self, text ):
        soup = BeautifulSoup( text, 'html.parser' )
        return soup.find( 'input', { 'name':'_csrf' } )['value']

    def fetchCsrf( self ):
        r = self.session.get( self.baseUrl )
        soup = BeautifulSoup( r.text, 'html.parser' )
        return soup.find( 'meta', { 'name': '_csrf' } )['content']

    def printHome( self ):
        print( self.session.get( self.baseUrl ).text )

    def addToCartTest( self ):
        payload = { 'FSTAT': '039', 'csrfToken': self.csrfToken, 'ID-00001': 1, 'PRICE-00001': '2499.99', 'NAME-00001': 'HK Mark 23', 'QUANTITY-00001': 2, 'ID-00002': 3, 'PRICE-00002': '647.00', 'QUANTITY-00002': 5, 'NAME-00002': 'Glock' }
        r = self.session.post( self.baseUrl + '/rest/cart', json = payload )
        return r.text

    def checkout( self ):
        payload = { 'FSTAT': '039', '_csrf': self.csrfToken, 'payment': 'RepHold' }
        r = self.session.post( self.baseUrl + '/checkout', data = payload )
        return r.text

    def didBuy( self, user, item ):
        ordersRaw = self.fetchOrders( user )
        #print( ordersRaw )
        #print
        #exit()
        orderList = json.loads( ordersRaw )
        #print( orderList )
        for o in orderList:
            for ol in o['orderLines']:
                if ol['product']['id'] == item['id'] and ol['quantity'] > 0:
                    return True
        return False

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

if __name__ == "__main__":
    print( "Buy some stuff!!" )
    #ab = AutoBuy( 'user', 'password' )
    ab = AutoBuy( 'admin', 'AncientMariner99' )
    #csrf = ab.fetchCsrf()
    #print( csrf )
    mk23 = ab.createItem( 'HK Mark 23', '1900.00', '2499.99', 'The finest handgun ever made.' )
    usp = ab.createItem( 'HK USP', '800.00', '1299.99', 'The gun Snake used on the Tanker Incident.' )
    g19 = ab.createItem( 'Glock', '475.00', '647.00', 'Popular mid-size handgun.' )
    a01ld = ab.createItem( 'CZ', '1800', '2200', 'Race gun with a telepathic trigger.' )

    print( ab.addStock( mk23, 1 ) )
    print( ab.addStock( usp, 25 ) )
    print( ab.addStock( a01ld, 3 ) )

    print( ab.fetchOrders( 'kowalski' ) )

    #print( ab.setMode( 'EASY' ) )
    #print( ab.setMode( 'HARD' ) )
