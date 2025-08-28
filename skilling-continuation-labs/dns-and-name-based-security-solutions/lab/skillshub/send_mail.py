#!/usr/bin/python3

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os, argparse, textwrap, json, smtplib, socket
import pandas as pd
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class CustomSMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        # Create a new socket and bind it to the IP address
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.bind((self.source_address, 0))
        new_socket.connect((host, port))
        return new_socket
        

class GiveHelp(argparse.Action):
    def __init__(self, nargs=0, **kw):
        super().__init__(nargs=nargs, **kw)
    def __call__(self):
        print(textwrap.dedent('''
            This script will allow you to specify specific configurations to allow you to send mail to various users.

            -r / --receiver argument format:
                1. Single email address. (Ex: test_user@lab.net)
                2. CSV File which contains multiple receipient addresses.
                    format: First column labeled 'addresses' with each host being its own record.

            -c / --content argument format:
                1. JSON formatted string containing the following key-value entries:
                    "subject":"**data**,
                    "body":"**data""
                2. CSV File which contains the data to be sent. It can contain multiple records to send multiple different emails.
                    format: first column labeled "header", second column labeled "body" where each record is its own email contents.
        '''))

## Attempting to use different source IP
def send_mail(data):
    ## Currently for testing, this variable below contains a list of IPs to be used as source IP. 
    # its manual, so if you want to test new IP, add it to this list
    #local_ips = ['123.45.67.202','123.45.67.204','123.45.67.205']
    for recv in data['recv']:
        for key, content in data['content'].items():
            if not recv.endswith('@lab.net'):
                if '@' in recv:
                    recv = recv.split('@',1)[0]
                recv = f"{recv}@lab.net"
            msg = MIMEMultipart()
            msg['From'] = data['sender']
            msg['To'] = recv
            msg['Subject'] = content['subject']
            msg.attach(MIMEText(content['body']))
            ## This variable below is what grabs whatever IP we want to use as source IP
            # if you want to test a specific IP, add it to the list above & then assign it here. 
            # as long as it exists in ifconfig/wherever else its setup, it should work here.
            ip = '10.5.5.5'
            try:
                with CustomSMTP(data['srvr'],int(data['port']),local_hostname=ip,timeout=10, source_address=ip) as server:
                    for _ in range(int(data['num'])):
                        server.sendmail(data['sender'],recv,msg.as_string())
            except smtplib.SMTPRecipientsRefused as e:
                print(f"Sending failed. Client host rejected: Access Denied")
            except Exception as e:
                raise Exception(f"Error occurred trying to send email to recipient: \"{recv}\". Please see attached error message:\n\t{e}")
            else:
                print(f"Sent {data['num']} emails successfully sent to \"{recv}\".")

def check_input(dtype, cur_data):
    fp = Path(os.path.abspath(cur_data))
    if dtype == 'r':
        if fp.is_file():
            try:
                recv_dict = pd.read_csv(fp,keep_default_na=False,na_filter=False).to_dict('index')
                recv_list = [value['addresses'] for key,value in recv_dict.items()]
                return recv_list
            except Exception as e:
                raise Exception(f"Error occured trying to read the file \"{cur_data}\". Please see attached error message:\n\t{e}")
        else:
            return [cur_data]
    else:
        content_dict = dict()
        if fp.is_file():
            try:
                content_dict = pd.read_csv(fp,keep_default_na=False,na_filter=False).to_dict('index')
            except Exception as e:
                raise Exception(f"Error occured trying to read the file \"{cur_data}\". Please see attached error message:\n\t{e}")
        else:
            try:
                cur_data = cur_data.replace("'", "\"")
                content_dict['0'] = json.loads(cur_data)
            except Exception as e:
                raise Exception(f"Error occurred trying to parse JSON string. Please see attached error message:\n\t{e}")
            return content_dict

def handle_args(args):
    data = {key: value for key, value in args.items() if value is not None}
    if ('sender' not in data.keys()): # and ('hf' not in data.keys())
        raise Exception("Missing argument '-s', no sender address specified.")
    elif ('recv' not in data.keys()): # and ('hf' not in data.keys())
        raise Exception("Missing argument '-r', no receiver address specified.")
    elif ('content' not in data.keys()):
        raise Exception("Missing argument '-c', email content not specified.")

    #if not data['sender'].endswith('@lab.net'):
    #if '@' not in data['sender']:
    #    data['sender'] = f"{data['sender']}@lab.net"

    data['recv']= check_input('r', data['recv'])
    data['content'] = check_input('c', data['content'])
    #print(json.dumps(data,indent=2))
    send_mail(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Mailer') # formatter_class=argparse.RawDescriptionHelpFormatter
    parser.add_argument('-i','--information', dest='info', help='Show information on how to use tool.', action=GiveHelp, default=None)
    parser.add_argument('-s','--sender', dest='sender', metavar='*SenderAddressStr*',help="Specify email address you want the email to be sent from.", action='store', default=None)
    parser.add_argument('-r','--receiver', dest='recv', metavar='*ReceiverAddressStr*',help='Requires single email address or CSV containing multiple email addresses you want to send emails to.',action='store',default=None)
    parser.add_argument('-p','--port', dest='port', metavar='*int*',help="Specify the port you want to send the mail to. ", action='store', default=25)
    parser.add_argument('-n','--num', dest='num', metavar='*int*', help="Specify the number of times you want to send each email. Will be sent that number of times per receipient.", action='store', default=1)
    parser.add_argument('-c','--content', dest='content', metavar='*ContentStr*', help='Requires either JSON formatted string or a CSV containing data you want sent in the mail. View "-i" ae format.',action='store',default=None)
    parser.add_argument('-S','--server', dest='srvr', metavar='*ServerStr*', help='Specify address of the SMTP server in network.',action='store',default="10.3.3.11")
    args, unknown = parser.parse_known_args()
    if unknown != []:
        print("Unknown arguments passed. Could not interpret the following data:")
        [print(f'\t{u}') for u in unknown]
        exit()
    try:
        handle_args(vars(args))
    except Exception as e:
        print(f"\nException:\n\t{e}")


