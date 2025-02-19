#!/usr/bin/python

import paramiko
import sqlite3
import subprocess
import logging

server = "finsta.us"
username = "user"
password = "L1k3AndSubscr1b3!?"

logging.basicConfig(
    filename='/var/log/challengeGrader/gradingCheck.log', 
    level=logging.INFO, 
    format='%(asctime)s %(levelname)s %(message)s')

def getTopoValue(name, default = "11deadbeef313373"):
    out = subprocess.run(f"vmtoolsd --cmd 'info-get guestinfo.{name}'", shell=True, capture_output=True)
    val = out.stdout.decode('utf-8').strip()
    if 'no' in val or name in val or val == "":
        logging.warning(f"USING DEFAULT TOKEN for {name}!!!")
        return str(default)
    return str(val)

def getDB():
    logging.info("Downloading socialmedia.db...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(server, username=username, password=password)

        sftp = client.open_sftp() 
        sftp.get("/home/user/app/instance/socialmedia.db", "/home/user/socialmedia.db")

        sftp.close()
    except Exception as e:
        print("GradingXSS: Greg did not find any posts about his interests")
        logging.error(f"Error retrieving socialmedia.db: {e}")
        exit(-1)

    logging.info("Downloaded socialmedia.db")

def readPosts():
    try:
        con = sqlite3.connect("/home/user/socialmedia.db")
        cur = con.cursor()
        res = cur.execute("SELECT username, tags FROM Posts")
        posts = res.fetchall()
        con.close()
    except Exception as e:
        print("GradingXSS: Greg did not find any posts about his interests")
        logging.error(f"Error querying socialmedia.db: {e}")
        exit(-1)

    good_posts = []
    great_posts = []
    for post in posts:
        count = 0
        for hobby in ["SunBattles", "FightTool40k", "PuzzleofChairs", "KingoftheBracelets"]:
            if hobby in post[1]:
                count += 1
        if count >= 4:
            great_posts.append(post)
            continue 
        if count >= 1:
            good_posts.append(post)

    if len(great_posts) == 0:
        if len(good_posts) == 0:
            logging.info("Greg found no posts tagged with his interests")
            print("GradingXSS: Greg did not find any posts about his interests")
        else:
            logging.info("Greg found no posts tagged with all of his interests")
            print("GradingXSS: Greg found a post(s) that covered some of his interests, but kept scrolling")

    users_to_visit = []
    for post in great_posts:
        if post[0] not in users_to_visit:
            users_to_visit.append(post[0])
    return users_to_visit

def runXSS(user, token):
    logging.info(f"Running XSS, visiting http://finsta.us/profile/{user}")
    try:
        result = subprocess.run(["node", "/home/user/challengeServer/custom_scripts/xss/doXSS.js", user, token], shell=False, capture_output=True, cwd="/home/user/challengeServer/custom_scripts/xss")
        logging.info(f"Got the following from stdout: {result.stdout}")
        logging.info(f"Got the following from stderr: {result.stderr}")
    except Exception as e:
        logging.warning(f"Potential error running XSS (note this may be acceptable): {e}")


if __name__ == '__main__':
    getDB()
    users = readPosts()
    token = getTopoValue("tokenXSS")
    for user in users:
        runXSS(user, token)
    if len(users) > 0:
        print(f"GradingXSS: Greg visited the profiles of the following users: {', '.join(users)}. The token is in his cookie for you to extract.")
