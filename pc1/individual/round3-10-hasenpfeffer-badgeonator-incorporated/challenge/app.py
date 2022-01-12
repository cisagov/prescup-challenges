"""
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
"""

from sqlalchemy.ext.declarative import DeclarativeMeta
from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey
from sqlalchemy import inspect
from flask import jsonify
import os
import uuid
from faker import Faker

basedir = os.path.abspath(os.path.dirname(__file__))
database_file = "sqlite:///{}".format(
    os.path.join(basedir, "app.db"))

app = Flask(__name__, template_folder='templates')
app.config["SQLALCHEMY_DATABASE_URI"] = database_file
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
engine = create_engine(database_file)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password = db.Column(db.String(128))

    def __repr__(self):
        return '<User {}>'.format(self.username)


class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(128), index=True, unique=True)

    def __repr__(self):
        return '<User {}>'.format(self.username)


@app.route('/')
def default():
    return render_template('/default.html')


# ' OR '1'='1' union SELECT 1, 2, 3, tbl_name FROM sqlite_master --
# ' OR '1'='1' union SELECT 1, 2, 3, value FROM flag --

# from bookmanager import db
#  > db.create_all()
#  > exit()

@app.route('/list', methods=["GET", "POST"])
def list():
    id = request.args.get('id')

    items = None

    # names = ["BunnyAbler","MindiGoudreau","DeedeeJanda","MargarettaRittenhouse","DinaValdes","SadeWolter",
    # "AdelaideRosier","TorrieCallan","RessieLachance","EmilyCilley","JeffryFickel",
    # "ShaeSaver","KrystinaNiswander","HeikePrete","StantonMinnis",
    # "JeannettaLeard","SanjuanitaOram","JasperHowser","LincolnRubino","JacintaNiemann","MildaBerlanga",
    # "BusterPal","DarrinJiles","ThereseGustafson","JudeSaracino","DelenaLamoureaux","BoydCienfuegos",
    # "CheryRinger","YukikoLohmann","OdetteSpring"]
    # for name in names:
    #     o = User(username=name, email=name +
    #              "@veritas.us.mil", password=str(uuid.uuid4()))
    #     db.session.add(o)
    # db.session.commit()

    with engine.connect() as con:

        faker = Faker()
        for i in range(60):
            try:
                statement = text("CREATE TABLE " + faker.word(ext_word_list=None) +
                                 "(id INTEGER NOT NULL,value VARCHAR(128),PRIMARY KEY(id))")
                items = con.execute(statement)
            except Exception as e:
                print(e)

        statement = text(
            "SELECT id, username, email, password FROM User where id = '" + id + "'")
        items = con.execute(statement)

        j = ""
        for row in items:
            j += str(row["id"]) + ", " + str(row["username"]) + \
                ", " + str(row["password"]) + "\n"

        #j = jsonify({'result': [str(row) for row in items]})

        print(j)

    return render_template("default.html", err=j)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    err = ""
    if request.method == 'POST':

        f = request.files['file']

        if(not f.filename.endswith(".png")):
            return render_temreturn_errorplate("That's not a .png image file, is it?")
        else:
            try:
                f.save("up/" + secure_filename(f.filename))
                d = decode(Image.open("up/" + secure_filename(f.filename)))

                id = d[0].data.decode("utf-8")
                print(id)

                items = None

                with engine.connect() as con:
                    statement = text(
                        "SELECT id, username, email, password FROM User where id = '" + id + "'")
                    items = con.execute(statement)

                    j = ""
                    for row in items:
                        j += str(row["id"]) + ", " + str(row["username"]) + \
                            ", " + str(row["password"]) + "\n"

                    #j = jsonify({'result': [str(row) for row in items]})

                    print(j)
                if len(j) > 0:
                    return render_template("default.html", err=j)
            except Exception as e:
                return render_template("default.html", err=e)
    else:
        return return_error("Why U not POST?")

    return return_error("Access Denied")


def return_error(err):
    return render_template('/default.html', err=err)


if __name__ == '__main__':
    app.run(debug=True)
