
# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from flask import Flask, request, render_template_string, make_response
import os, sys, datetime
app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
    if not request.cookies.get('cookie'):
        res = make_response("You are not an admin.<br>Only admins can view the token.")
        res.set_cookie('cookie', gen_cookie(), max_age=60)
    else:
        if not is_admin(request.cookies.get('cookie')):
            res = make_response("You are not an admin.<br>Only admins can view the token.")
        else:
            with open('token.txt', 'r') as f:
                res = make_response(f"You are an admin.<br>Your token is: {f.readline()}")
    return res

####
# Private function
###

def gen_cookie():
    cookie = """
    date=%s ;
    comp=PresCup ;
    version=2 ;
    loc=Washington,DC ;
    first=Harry ;
    last=Bovik ;
    f1=doZKrERyF4ukrLOkwjBl7oHPTOnb1dpg;
    f2=PrROkRBWfBqN5QfquhGnuzcaGOwab10z;
    f3=FB3A43A8FEDAF2814F7D6BB962488;
    f4=1r3oH1n{24T^f?d68{7^(Z-[*mSVu/?at5]([4s[hJj7OQqjd4WKqRiqqP;
    lkQPt=OdbJv6siTRJ5uFhNubQFjgz5DCZmZOt4;
    wtvA3=vReratb3batjW4GmQfUJZvSXvQneDmeR;
    XzQBW=jBocrEZlQJtWK5nSbKYMXh9fC08RF1PK;
    twyvb=83BjWpcMd1pQcpSPsmX5Ebee4OO3beLn;
    KoaUV=vtiI8kTgmd1srCIytMRSVpTs7tipNvib;
    MYU16=ngQoMeER6wXUdokPkMUf8QdaQAjX7j8v;
    wAQRY=aHnRDQpGwHTqTZoG8FSmri5W9k4gn7h1;
    C4CEb=6XK2tJIbsXP0LXfmQONUu41u4UdGjO4p;
    AaTjC=KnRlep2EsXEez7BIBCNRaL9Pch5UmeDj;
    tQ3KF=RW81wMwUU9YwiNAI0CgmKgACw25E21nu;
    Wgrl7=m2gFlNTlknds8iWfVOdZa4XLiGuKzOYe;
    PmPzS=Kvfb1nz84AUrRBtcloXbIM7jnXgpSsm4;
    Sk0hP=BOFKswbH81iCglSKDwXYLXjyKEmIBGaH;
    mLknq=nD9dzP7wlu9YZ5BQUyZTW6nn9s7rCZg5;
    wjqrW=wycD11y2GUQLzJ98IjufsVlRcd20GCE2;
    ptYa4=J699aYzZW7FaEhAW2QgyDWadzlBMe3BH;
    q4SeR=w0s5kNyOw1o9yMbyqcidReSOtuBEEvVE;admin=no;VZu4Q=4FcabgUoFNbE4AtOpzXwxtJBtywFDNFY;
    oCtkA=eXRhuwY8KzxVsNrUgKkPzeTGrOgcQuTH;
    C6pxt=Sdi98W76W9HdIY2pPET1Pt7eMn49McQv;
    rs3uf=3VZk0kRFmtiPx8NL0abm
    ihz27=JgRtInEsNMr5Lx3krJLM
    eH9cT=KqVgrxlf405HjfBf1xtp
    zPinf=FJmUJdZAHBgsSMeXSjpq
    6oTxZ=rmh20mvLgf6GVocu0duI
    VKrXb=kkNHgOYsXYdZQ1zbP6Dw
    iFJVR=hytPfgfMRTxghEy7bK2n
    lIcyI=kNzSiKeLzgdaHkYA7fqE
    CcPx9=3RNUJaIjxHGH21AHcRkI
    9iWcR=DTvVyt6jxUPt9JGxezcu
    VQ4pC=nQ7R1yIxRl5QXTnB2nqj
    sky7P=z2a2tXzqslkm2Rgwq8tV
    nf68Z=9prOcWU0lmvSSQpGxn7D
    PnFVJ=zRVCMBwfGdG5JECUTrQs
    5FpKl=m1j1r7z2U4Z90fMIa8JT
    """ % datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
    import base64
    return base64.b64encode(cookie.encode('utf-8'))

def is_admin(cookie):
    import base64
    if 'admin=yes' in base64.b64decode(cookie).decode('utf-8'):
        return True
    return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
