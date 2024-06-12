
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

⚙
⚙
If the "Tools" button is in the way, hide it here. If hidden, you can open the tools panel by moving the mouse to the left edge of the console.

Show tools button: 
System
Ctrl-Alt-Del
Reset Power
Screen
Toggle Scale
Sync Resolution
Enter Fullscreen
Show Device Keyboard
Network
Refresh
nic1
nic2
nic3
Clipboard
COPY transfers the vm clip to your clipboard. Select/Copy text in the vm using crtl-c or context menu before clicking COPY here. (Clicking COPY shows text below *AND* adds to your clipboard.)

PASTE sends the text below to the vm. Ensure the vm cursor is focused in a window that accepts keyboard input before clicking PASTE here.

⇧ Copy
⇩ Paste
Clear
#!/bin/bash

token1=$(vmtoolsd --cmd "info-get guestinfo.token1")
token2=$(vmtoolsd --cmd "info-get guestinfo.token2")
NewPassword="ComplexPassword123-"

echo "$token1" > /home/user/Desktop/docker-php-nginx/src/flag_one.txt
echo "$token2" > /home/user/Desktop/flag_two.txt

expect /home/user/challengeServer/custom_scripts/expectscript.sh user tartans user@app-server.merch.codes $NewPassword &

./home/user/challengeServer/custom_scripts/randomCoupon.sh

mv /home/user/challengeServer/src/coupons.txt /home/user/Desktop/docker-php-nginx/src/coupons.txt

docker build -t registry.merch.codes:5000/coupons:latest /home/user/Desktop/docker-php-nginx/
docker push registry.merch.codes:5000/coupons:latest

# sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/web/"
# web_pod_name=""
# while [[ -z $web_pod_name ]]; do
#     web_pod_name=$(sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl get pods -o name -n coupons | grep coupons | head -n1 | awk '{print $1}' 2>/dev/null")
#     if [[ -z $web_pod_name ]]; then
#         echo "Waiting for pod to be created..."
#         sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/web/"
#         sleep 3
#     fi
# done

# sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/tools/"
# tool_pod_name=""
# while [[ -z $tool_pod_name ]]; do
#     tool_pod_name=$(sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl get pods -o name -n coupons | grep tools | head -n1 | awk '{print $1}' 2>/dev/null")
#     if [[ -z $tool_pod_name ]]; then
#         echo "Waiting for pod to be created..."
#         sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/tools/"
#         sleep 3
#     fi
# done

sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/web/"
sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl wait --for=condition=ready pod -l app=coupons"
sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/tools/"


# while true; do
#   is_up=$(curl -s -o /dev/null -w "%{http_code}" https://coupons.merch.codes)

#   if [[ $is_up != 200 ]]; then
#     sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl delete deployment coupons --force --grace-period=0"
#     sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/web/"

#     while [[ $(sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl get pods -l app=coupons -o 'jsonpath={..status.phase}'") != 'Running' ]]; do
#         sleep 1
#     done

#   else
#     break
#   fi
# done




# coupons_up=$(curl -s -o /dev/null -w "%{http_code}" https://coupons.merch.codes | grep -q 200 || echo 1)
# while [[ $coupons_up != 200 ]]; do
#     sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl delete deployment coupons --force --grace-period=0"
#     sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl apply -f /home/user/coupons/web/"
#     sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS kubectl wait --for=condition=ready pod -l app=coupons"
#     sleep 10
#     coupons_up=$(curl -s -o /dev/null -w "%{http_code}" https://coupons.merch.codes | grep -q 200 || echo 1)
# done

sudo -u user sshpass -p ComplexPassword123- scp /home/user/Desktop/flag_two.txt user@k3s-server.merch.codes:/home/user/
sudo -u user sshpass -p ComplexPassword123- ssh user@k3s-server.merch.codes "echo ComplexPassword123- | sudo -sS mv /home/user/flag_two.txt /root/"


