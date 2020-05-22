#!/usr/bin/python3

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

---

main challenge builder...
gpx files saved by hash id
hash gives you x number of gxp to analyze
writing out those gpx spells out a particular hike on google maps — https://www.gpsvisualizer.com/draw/

encrypt.py works to encrypt clue strings that geo is where flag lives

"""
import psycopg2
import gpxpy
import gmplot
import matplotlib.pyplot as plt
import matplotlib.dates as pltDates
import random
import os
import shutil
import time
import string
import uuid
from faker import Faker
from faker_wifi_essid import WifiESSID
from faker.providers import internet
from cryptography.fernet import Fernet
import errno

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def get_username():
    line = random_line("usernames.txt")
    return line
    
def get_savepath(basepath, username):
    savepath = random_line("savepaths.txt").replace("[username]", username)
    return basepath + savepath

def random_line(afile):
    lines = open(afile).read().splitlines()
    return random.choice(lines)

def get_records():
    try:
        connection = psycopg2.connect(user="gpx", password="tartans@1", host="localhost", port="5432", database="gpx")
        cursor = connection.cursor()
        cursor.execute("SELECT name, gpx FROM gpx limit 10;") # LIMIT 1 for testing
        records = cursor.fetchall()
        return records
    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL", error)
    finally:
        #closing database connection.
        if(connection):
            cursor.close()
            connection.close()

def copy_file(basepath, f, outfile_name):
    fixed_file = open(f).read()
    with open(basepath + outfile_name, "w") as f:
                f.write(fixed_file)

def generate_profiles(current_dir):
    faker = Faker()
    """generate people profiles using faker, so that it looks like stolen identities"""
    for _ in range(random.randint(122, 548)):
        name = faker.name()
        dir = current_dir + "profiles/" + name + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)

        chance = random.randint(0, 1)
        if chance > 0:
            continue
        
        file = open(dir + faker.file_name(category=None, extension=None), "w")
        file.write(faker.text(max_nb_chars=200, ext_word_list=None))
        file.close()

        for i in range(random.randint(2, 22)):
            with open(dir + "/%s-%s.bin" % (time.time(), i), "wb") as fout:
                fout.write(os.urandom(random.randint(1, 2048)))
                fout.close()


def generate_logs(current_dir, folder):
    for _ in range(100):
        line = randomString()
        dir = current_dir + folder + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)
        dir += line + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)
        else:
            continue

        chance = random.randint(0, 1)
        if chance > 0:
            continue

        for i in range(random.randint(0, 22)):
            with open(dir + "%s-%s.log" % (time.time(), i), "wb") as fout:
                fout.write(os.urandom(random.randint(1, 1024)))
                fout.close()

def generate_folders(current_dir, folders):
    base_dir = current_dir
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    for folder in folders:
        dir = base_dir + folder + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)


def generate_pii(current_dir, folder, rng):
    base_dir = current_dir + folder + "/"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    for count in range(rng):
        faker = Faker()
        line = faker.profile()
        dir = base_dir + line["username"][0] + "/"
        if not os.path.exists(dir):
            os.makedirs(dir)

        with open(dir + "%s-%s-%s.json" % (line["username"], time.time(), count), "w") as fout:
            fout.write(str(line))
            fout.close()


def copy_map_gpx(current_dir, savepath):
    fake = Faker()
    fake.add_provider(internet)
    fake.add_provider(WifiESSID)
    wifi = "{" + str(fake.wifi_essid()) + ":" + str(fake.ipv4_private()) + "}"

    current_directories = []
    current_directories = get_directories(savepath)

    for f in os.listdir(current_dir):
        gpx = gpxpy.parse(open(current_dir + f).read())
        if(len(gpx.tracks) > 0):
            for track in gpx.tracks:
                for segment in track.segments:
                    for point in segment.points:
                        if random.random() < 0.25:
                            wifi = "{" + str(fake.wifi_essid()) + \
                                ":" + str(fake.ipv4_private()) + "}"
                        point.name = wifi

        if not os.path.exists(savepath):
            os.makedirs(savepath)

        # find random home for map files
        save_in_dir = random.choice(current_directories)
        savepath = save_in_dir + "/" + str(uuid.uuid1()) + ".gpx"
        #print("writing map solution file to " + savepath)
        solution_files.append("MAP|" + savepath)

        with open(savepath, "w") as f:
            f.write(gpx.to_xml())


def get_directories(folder):
    dirs = []
    for root, directories, files in os.walk(folder):
        for d in directories:
            o = os.path.join(root, d)
            dirs.append(o)
    return dirs
    
### end classes and functions


solution_files = []


# clean up and reset output folder
appbasepath = "../output/"
if os.path.exists(appbasepath):
    shutil.rmtree(appbasepath)

flags = ["{Joshua-Terrey-Wifi:172.25.200.111}", "{Joshua-Terrey-Hotspot:172.29.228.192}", "{Joshua-Terrey-Ship:172.30.226.19}"]
records = get_records()
folders = ["bind", "_64fb760c-1553-477c-b2f7-1d94447911ed", "conf", "dat", "drivers", "bin", "samsung", "tor", "logs",
                "profiles", "raw", "txt", "var"]

for challenge_number, currentFlag in enumerate(flags):
    wasFlagWritten = False
    currentFlag = flags[challenge_number]
    print("Building challenge " + str(challenge_number))
    basepath = appbasepath + "T2-AI500-00" + str(challenge_number) + "/"

    for record in records:
        name = record[0]
        gpx = gpxpy.parse(record[1])
        
        """ 
        add wifi to gpx, change it every so often
        """
        fake = Faker()
        fake.add_provider(internet)
        fake.add_provider(WifiESSID)
        wifi = "{" + str(fake.wifi_essid()) + ":" + str(fake.ipv4_private()) + "}"

        user = get_username()
        savepath = get_savepath(basepath + "geo/", user)
        filepath = savepath + str(uuid.uuid1()) + ".gpx"
        #savepath = basepath + "geo/"
        #filepath = savepath + "test.gpx"

        if(len(gpx.tracks) > 0):
            for track in gpx.tracks:
                for segment in track.segments:
                    for point in segment.points:
                        if random.random() < 0.25:
                            wifi = "{" + str(fake.wifi_essid()) + ":" + str(fake.ipv4_private()) + "}"
                        if not wasFlagWritten and random.random() < 0.004:
                            print("FLAG WRITTEN:" + currentFlag + ":" + filepath)
                            solution_files.append("FLAG|" + filepath)
                            wifi = currentFlag
                            wasFlagWritten = True
                        point.name = wifi

        if not os.path.exists(savepath):
            os.makedirs(savepath)
        
        with open(filepath, "w") as f:
            f.write(gpx.to_xml())

    # write solution maps
    copy_map_gpx("solution/", basepath + "geo/")
    # write fixed files
    copy_file(basepath, "solution_readme", "README")
    copy_file(basepath, "requirements.txt", "requirements.txt")

    generate_folders(basepath, folders)
    generate_profiles(basepath)
    generate_logs(basepath, "logs")
    generate_pii(basepath, "var", 333)

    for folder in folders:
        if os.listdir(basepath + folder) == []:
            faker = Faker()
            for i in range(random.randint(22, 212)):
                file = open(basepath + folder + "/" + faker.file_name(category=None, extension=None), "w")
                file.write(faker.text(max_nb_chars=200, ext_word_list=None))
                file.close()

    
with open("generate_results.txt", "w") as f:
    for item in solution_files:
        f.write("%s\n" % item)
