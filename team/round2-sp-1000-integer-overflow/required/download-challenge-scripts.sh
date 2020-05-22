#!/bin/bash

# President's Cup Cybersecurity Competition 2019 Challenges
#
# Copyright 2020 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
# FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
# OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
# MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# DM20-0347

known_hashes=('d0fc2a550b8e7090c33cf2331a6f9648508d4776 _bz2module.c Modules/_bz2module.c'
              'c2a94459fab2bf0fc8b281d2dcfaa47db0299a03 bytearrayobject.c Objects/bytearrayobject.c'
              '804d4c1db27bb191baf2ec6dfcd0c25bdc694688 cmathmodule.c Modules/cmathmodule.c'
              '19e2d4e9ef80404cabb68abe796cede36bf13e69 _functoolsmodule.c Modules/_functoolsmodule.c')


for hash_str in "${known_hashes[@]}"; do
  known_digest="$(echo $hash_str | awk '{print $1}')"
  file="$(echo $hash_str | awk '{print $2}')"
  path="$(echo $hash_str | awk '{print $3}')"

  if [ ! -f "$file" ]; then
    curl -O "https://raw.githubusercontent.com/python/cpython/382ff63aa17856475bb81dbf24df3ac36c60c4e3/$path"
  fi

  new_digest="$(shasum $file | awk '{print $1}')"

  if [ "$new_digest" != "$known_digest" ]; then
    echo "File $file hash does not match the expected hash. Output from this script may not be correct."
  fi
done

cat _bz2module.c | sed 1,249d | sed 37,87d | head -n 45 > file1
cat bytearrayobject.c | sed 1,187d | sed 6,7d | sed 5G | head -n 77 > file2
cat cmathmodule.c | sed 1,399d | sed 127d | sed 118,119d | sed 58d | sed 3d | sed 78d | sed 114G | sed 122G | sed 's/\/\* safe from overflow \*\///g' | head -n 130 > file3
cat _functoolsmodule.c | head -n 113 | sed 1,27d | sed 's/pto->use_fastcall = _PyObject_HasFastCall(func);/partial_setvectorcall(pto);/g' > file4

trimmed_hashes=('b11cc5016155f44e9a97ed1967e406d860dcc7cd file1'
                '1db92ae97e69ddfa8b382ab31b6c77f2e0949b38 file2'
                '1a6790bc5ff840c6db94f1aff793f56402de6f05 file3'
                '48d0e265317c1e0dc9b98c09f085eed66f10bf75 file4')

for hash_str in "${trimmed_hashes[@]}"; do
  known_digest="$(echo $hash_str | awk '{print $1}')"
  file="$(echo $hash_str | awk '{print $2}')"

  new_digest="$(shasum $file | awk '{print $1}')"

  if [ "$new_digest" != "$known_digest" ]; then
    echo "File $file hash does not match the expected hash. Output from this script may not be correct."
  fi
done
