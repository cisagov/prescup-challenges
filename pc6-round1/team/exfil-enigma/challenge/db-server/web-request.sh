#!/bin/bash
#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
# DM25-0166#


for (( ; ; ))
do
    token4=$(cat /home/user/Documents/token4.txt)
    token="Token 4: "
    token="${token} ${token4}"
    encoded=$(echo -n $token | base64)
    curl -i -X GET 123.45.67.189:80/about.html
    sleep 10
    curl -i -X GET 123.45.67.189:80/faq.html -H "Session: ${encoded}"
    sleep 10
    curl -i -X GET 123.45.67.189:80/home.html
    sleep 10
    curl -i -X GET 123.45.67.189:80/faq.html
    sleep 10
done

