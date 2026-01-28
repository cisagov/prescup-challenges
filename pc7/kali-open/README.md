# Kali VNC Workstation

This directory contains the files necessary to recreate the Kali workspace used in the President's Cup.

## Running a challenge

1. First, build your Kali workstation: `docker compose up -d --build`  
    - This will take a while, as it needs to install all of the Kali tools. 
    - This will also create a "competitor_net" network, which all of the challenges will connect to.

2. Once the Kali container is up and running, visit `http://localhost:6080/vnc.html` in your browser. You should be connected to the NoVNC interface. Press "Connect", and you should see the Kali Desktop.
3. Navigate to the `challenge` directory of the challenge you would like to run.
4. Edit the `docker-compose.yml` file to uncomment the `external: true` line for the challenge so that it can connect to your Kali instance. A simple example is provided below
   
``` yaml
services:
  web:
    image: nginx
    networks:
      - competitor_net # competitor will have direct access to this container from their workstation.
      - target_app_net # this container can see (is on the same network as) the app container.

networks:
  competitor_net:
    # There should be a competitor_net with "external: true" commented out. Remove the # to uncomment the line, or add the "external: true" if it is missing
    external: true # This will connect the challenge to the existing Kali competitor_net
  target_app_net:
    # Any other networks are private networks specific to the challenge, and should not be modified
    driver: bridge
```

5. Now run `docker compose up -d --build` in the challenge directory to launch the challenge.
6. You should now have access to the challenge in your Kali VNC.

## Switching challenges

To switch the challenge you are connected to, first run `docker-compose down` in the current challenge directory.

Next, repeat steps 3-6 of [Running A Challenge](#running-a-challenge) to launch the new challenge.

## Resetting your Kali workspace

If something goes wrong with your Kali workspace, you can run `docker compose down` in the Kali directory to stop it, and then run `docker compose up -d --build` again to restart it. This will return it to the default state.

Note that you do *not* need to stop the challenge containers first to restart Kali.