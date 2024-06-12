
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

def modify_file_inplace(filename, crypto, blocksize=16):
    '''
    Open `filename` and encrypt/decrypt according to `crypto`

    :filename: a filename (preferably absolute path)
    :crypto: a stream cipher function that takes in a plaintext,
             and returns a ciphertext of identical length
    :blocksize: length of blocks to read and write.
    :return: None
    '''
    with open(filename, 'r+b') as f:
        try:
            plaintext = f.read(blocksize)

            while plaintext:
                ciphertext = crypto(plaintext)
                if len(plaintext) != len(ciphertext):
                    raise ValueError('''Ciphertext({})is not of the same length of the Plaintext({}).
                    Not a stream cipher.'''.format(len(ciphertext), len(plaintext)))

                f.seek(-len(plaintext), 1) # return to same point before the read
                f.write(ciphertext)

                plaintext = f.read(blocksize)
        except IOError as e:
            print("Error \n" + e.erno)

