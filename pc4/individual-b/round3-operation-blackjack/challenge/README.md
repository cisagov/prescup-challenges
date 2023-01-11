# Operation Blackjack

_Setting Up_

1. Create a Kali VM and copy the [challenge folder](.) to the desktop.
>NOTE: For the offline version of this challenge, we have purposely disabled the use of sudo command. You can always use 'su root' with the password 'tartans' to access your root account in case you need it for something NOT related to the challenge since you won't need to be root for this challenge. Doing this allows us to simulate you not having permissions to read files from the gyre account unless you exploit the correct vulnerability. Using sudo would allow you to bypass this, so we disabled it to provide a more accurate simulation of the actual challenge. Make sure you are using a VM to avoid losing any important data. 

2. Give setup files executable permissions by running the following commands: 
```bash
cd Desktop/challenge/
chmod +x deploy_challenge.sh
```

3. Deploy the challenge using [deploy_challenge.sh](./deploy_challenge.sh) (For this script, make sure you are not root):
```bash
./deploy_challenge.sh
```

Once that script finishes running, you can begin the challenge. 

>Note: The [deploy_challenge.sh](./deploy_challenge.sh) shell script was not provided in the actual competition, instead, it is going to be used just once to set up your environment for this challenge. Seeing the contents written inside the [deploy_challenge.sh](./deploy_challenge.sh), [grade.sh](../grade.sh) and any files inside the [/initialize directory](./initialize) will reveal the answers for this challenge.

