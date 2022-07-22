#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import paramiko
import time
import yaml

def backup(backup_config):

  import datetime

  with open(backup_config.config) as stream:
      config = yaml.safe_load(stream)


  print("Backing up host: " + config['host'])
  
  backup_name = config['host']+'-'+datetime.datetime.now().strftime("%Y%m%d-%H%M")+'.tar.gz'

  target = ''
  for mount in config['mount_points']:
      target = target + ' '+ mount


  key = paramiko.RSAKey.from_private_key_file('/home/user/.ssh/id_rsa')
  ssh_client = paramiko.SSHClient()
  ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  
  ssh_client.connect(hostname = config['host'], username = 'user', pkey=key)
  stdin, stdout, stderror = ssh_client.exec_command('/usr/bin/sudo /usr/local/bin/backup.sh '+backup_name+target)
  ssh_client.close()

  if config['backup_host'] and exit_status == 0:
      print("Copying backup: "+backup_name+" to: "+config['backup_host'])
      ssh_client.connect(hostname = config['backup_host'], username = 'user', pkey=key)
      sftp = ssh_client.open_sftp()
      sftp.put('/home/user/'+backup_name,'/home/user/'+backup_name)
      sftp.close()
      ssh_client.close()

def restore(restore_config):

  import subprocess

  print("Someone call for a restore?")
  print('restore_config.config')

  with open(restore_config.config) as stream:
      config = yaml.safe_load(stream)
   
  key = paramiko.RSAKey.from_private_key_file('/home/user/.ssh/id_rsa')
  ssh_client = paramiko.SSHClient()
  ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

  ssh_client.connect(hostname = config['backup_host'], username = 'user', pkey=key)

  if config['backup_host']:
      print("Copying backup: "+config['backup_name']+" from "+config['backup_host'])
      sftp = ssh_client.open_sftp()
      sftp.put('/home/user/'+config['backup_name'],'/home/user/restore-'+config['backup_name'])
      sftp.close()

  cmd = ['/home/user/restore.sh','restore-'+config['backup_name']]

  restore = subprocess.Popen(cmd,shell=False)
  restore = restore.communicate()


def main():

  import argparse

  parser = argparse.ArgumentParser()
  subparser = parser.add_subparsers()

  backup_parser = subparser.add_parser('backup')
  backup_parser.add_argument(nargs='?',dest='config',default='backup.yaml')
  backup_parser.set_defaults(func=backup)

  restore_parser = subparser.add_parser('restore')
  restore_parser.add_argument(nargs='?',dest='config',default='restore.yaml')
  restore_parser.set_defaults(func=restore)

  args = parser.parse_args()
  args.func(args)

if __name__ == '__main__':
    main()

