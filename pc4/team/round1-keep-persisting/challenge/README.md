# Keep Persisting!

_Setting Up_


1. Create a Ubuntu VM and copy the [challenge folder](.) to the desktop.

2. Give setup files executable permissions by running the following commands: 
```bash
cd Desktop/challenge/
chmod +x prepare_system.sh
chmod +x deploy_challenge.sh
```

3. Run the [prepare_system.sh](./prepare_system.sh) script **as root**:
```bash
sudo su
./prepare_system.sh
```

4. Deploy the challenge using [deploy_challenge.sh](./deploy_challenge.sh) (For this script, make sure you are no longer root):
```bash
./deploy_challenge.sh
```

Once that script finishes running, you can begin the challenge. 

>Note: The [prepare_system.sh](./prepare_system.sh) and [deploy_challenge.sh](./deploy_challenge.sh) shell scripts were not provided in the actual competition, instead, they are going to be used just once to set up your environment for this challenge. Seeing the contents written inside the [prepare_system.sh](./prepare_system.sh), [deploy_challenge.sh](./deploy_challenge.sh), [grade.sh](../grade.sh) and any scripts inside the [/scripts directory](./scripts) will reveal the answers for this challenge.
