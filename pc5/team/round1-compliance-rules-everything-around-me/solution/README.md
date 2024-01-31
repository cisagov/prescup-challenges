# Compliance Rules Everything Around Me

*Solution Guide*

## Overview

Scan and fix the network topology of an Aurelian spaceship. Identify and address weaknesses in the system, including: default application passwords, open ports, firewall rules, and misconfigurations. The Kubernetes environment must work correctly after making changes.

#### Important! 

To solve *Compliance Rules Everything Around Me* you must have knowledge of Kubernetes deployments and best practices. Parts of the challenge involve changing administrative passwords; changing them without making the necessary changes to the Kubernetes manifest will make the challenge more difficult. Services won't redeploy, applications won't connect to databases, etc. This solution guide walks you through the recommended order of steps to solve in order to avoid those difficulties. However, if you prefer to perform the challenge in a different order, feel free to do so.

## Question 1

*Password Management Control*

Upon reading the *Security Control Guide*, the first security control you want to confirm is being met is **Password Management**. This control is divided into two parts. Part 1 tells you passwords must meet uniqueness and complexity requirements. They are: 

- Minimum length: 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

Part 2 tells you "in applications that allow users to create their own account, you must enforce password complexity by correctly configuring the necessary options."

Here is the list of applications that have the default password (*tartans*):

- Mattermost (https://chat.merch.codes)
- K3s Postgres
- Keycloak (https://keycloak.merch.codes)
- PGAdmin (https://db.merch.codes)

Let's start changing some passwords. 

### Part 1

#### Mattermost

First, let's change Mattermost: 

1. From your Kali VM, go to `https://chat.merch.codes`.
2. Log in using the admin credentials (admin/tartans).
3. Click **Go to System Console**.
4. In the left navigation bar, click **Users**, **@admin**.
5. Click **Reset Password** and enter your new password. We will use `MattermostPassword123-` because it's easy to remember and meets the complexity requirements above.

If you change an administrative password of an application being hosted by Kubernetes, you should check to see if changes are needed in the manifest. In the case of Mattermost, when it is deployed for the first time it asks that the admin user be created, which has already been addressed.

#### Postgres

Now, let's do Postgres:

1. ssh into k3s-server using the provided credentials (user/tartans):
```bash
ssh user@10.3.3.10
```
2. `sudo su` and enter the provided password.
3. Once you are `root`, look to see which pods are running in the cluster: 
```bash
kubectl get pods
```
You should get an output similar to the following. Your name might have a different ending; make sure to use the name you see in your output. 

```
NAME                              READY   STATUS    RESTARTS      AGE
dnsutils                          1/1     Running   4 (44m ago)   9d
postfix-b4c4c6cd9-hcd4m           1/1     Running   4 (44m ago)   9d
pgadmin-75bbbcd6fd-4kltx          1/1     Running   4 (44m ago)   9d
tools                             1/1     Running   4 (44m ago)   9d
dovecot-d98c9fcb-szwz7            1/1     Running   4 (44m ago)   9d
roundcubemail-5bb69f69bf-vcvbt    1/1     Running   4 (44m ago)   9d
postgres-587f4b6f7d-hkc8w         1/1     Running   4 (44m ago)   9d
mattermost-app-7d7dc448cb-tfdvl   1/1     Running   4 (44m ago)   9d
keycloak-7d8669fffc-wwgx9         1/1     Running   1 (44m ago)   3d
```

4. Go inside the postgres pod:
```bash
kubectl exec --stdin --tty postgres-587f4b6f7d-hkc8w -- /bin/bash
```
>Note: If you receive an error from the server saying `503 Service Unavailable`, it means the database is still performing tasks in the background. Give it a few minutes to finish. 

5. Start making changes to the postgres configuration: 
```bash
psql -U root -d postgres
```
​	This will prompt you for the password. Use the provided password (tartans). Once you log into postgres, it's time to change the password. 

6. Type the following query to change the root user's password: 
```
alter user root with password 'PostgresPassword123-'; 
```
​	We will use `PostgresPassword123-` because it's easy to remember and meets the complexity requirements above.

Once the root user's password is changed, you can exit out of the postgres pod by typing the following command twice: 

```
exit
```

7. Check the postgres deployment manifests to see if the password needs to be changed there too. Under `/home/user/default/postgres/postgres-secret.yaml` we can see that it sets the root user and the root password. Here is the file: 
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: postgres-secret
  labels:
    app: postgres
type: Opaque
data:
    postgres-root-username: cm9vdA==
    postgres-root-password: dGFydGFucw==
```
​	Both the root user and password are base64 encoded. 

8. Decode them from the terminal by entering: 
```bash
echo "cm9vdA==" | base64 -d
echo "dGFydGFucw==" | base64 -d
```

Based on this, upon deployment, postgres is setting a root user with username `root` and password `tartans`. Since we changed the password to `PostgresPassword123-`, we need to change the last line to reflect this.

9. Base64 encode the ***new*** postgres password:

>Note: Notice the `-n` in the command below -- this is very important.

```bash
echo -n "PostgresPassword123-" | base64
```
The output will be: `UG9zdGdyZXNQYXNzd29yZDEyMy0=`.

10. Edit the `postgres-root-password` line in the `postgres-secret.yaml`. The file now looks like this: 
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: postgres-secret
  labels:
    app: postgres
type: Opaque
data:
    postgres-root-username: cm9vdA==
    postgres-root-password: UG9zdGdyZXNQYXNzd29yZDEyMy0=
```
#### Keycloak

Next, we'll do Keycloak:

1. From your Kali VM, go to `https://keycloak.merch.codes`.
2. Log in using the provided admin credentials (admin/tartans). You are in the `master realm`.
3. On the left navigation bar, click **Users**, click **Admin**.
4. On the top navigation bar, click **Credentials**.
6. Click **Reset Password** and type your new password. We will use `KeycloakPassword123-` because it is easy to remember and meets the complexity requirements above.
7. Once the password is changed, go to the Keycloak manifest. These are the lines we want to see in the Keycloak deployment manifest:
```yaml
        - name: KEYCLOAK_ADMIN_PASSWORD
          value: 'tartans'
        - name: KC_DB_PASSWORD
          value: 'tartans'
```
8. Because we just changed the Keycloak admin password from `tartans` to `KeycloakPassword123-`, we need to change the `KEYCLOAK_ADMIN_PASSWORD` line. We also changed the database root password from `tartans` to `PostgresPassword123-`. Here are the new lines we want to see for that file: 
```yaml
        - name: KEYCLOAK_ADMIN_PASSWORD
          value: 'KeycloakPassword123-'
        - name: KC_DB_PASSWORD
          value: 'PostgresPassword123-'
```

#### PGAdmin

Finally, let's do PGAdmin: 

1. From Kali VM, go to `https://db.merch.codes`. 
2. Log in using the provided admin credentials (`admin@merch.codes`/tartans)
3. Select **admin@merch.codes(internal)** from the dropdown, then **Change Password**. Type in your new password. We will use `PgadminPassword123-` because it is easy to remember and meets the complexity requirements above.
4. Once the password is changed, go to the PGAdmin deployment manifest, which is referencing the `pgadmin-secret.yaml`: 
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pgadmin-secret
type: Opaque
data:
  pgadmin-default-password: dGFydGFucw==
```
5. Decode the password (it's `tartans`).
6. Base64 encode the new password. This is the result: `UGdhZG1pblBhc3N3b3JkMTIzLQ==`
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pgadmin-secret
type: Opaque
data:
  pgadmin-default-password: UGdhZG1pblBhc3N3b3JkMTIzLQ==
```

Now, for all those manifest changes to take effect, redeploy the applications we updated. Here is a quick way: 
```bash
kubectl get deployments
kubectl delete deployment keycloak
kubectl delete deployment postgres
kubectl delete deployment pgadmin
kubectl delete deployment mattermost-app
kubectl apply -f /home/user/default/keycloak/
kubectl apply -f /home/user/default/postgres/
kubectl apply -f /home/user/default/pgadmin/
kubectl apply -f /home/user/default/mattermost/
```

#### Grading Part 1

Now that all passwords have been changed, go to the "Compliance Assistant" on https://challenge.us from a gamespace resource and enter the new passwords ***one by one***. Make sure you select the correct service/application from the dropdown. You will receive the first half of the first token. To get the second half, you will enforce password complexity by correctly configuring the applications that allow users to create their own accounts in Part 2. 

### Part 2
---
The two applications that allow users to create their own account are **Roundcube Mail** (https://mail.merch.codes) and **Mattermost** (https://chat.merch.codes). 

#### Mattermost

Let's start enforcing password complexity on Mattermost: 

1. From your Kali VM, browse to `https://chat.merch.codes`. 
2. Log in using the provided admin credentials (admin/tartans).
3. Click **Go to System Console**.
4. On the left navigation bar, type **Password**. 
5. Check the options to meet complexity requirements.

#### Roundcube

Roundcube is tricky because it uses Keycloak as OAUTH to allow users to log in, but if you go to `https://mail.merch.codes`, you can see users can also register for an account. So, to enforce password complexity on Roundcube Mail we need to change some configurations on Keycloak. 

1. From your Kali VM, browse to `https://keycloak.merch.codes`.
2. Log in using the provided admin credentials (admin/tartans). If you go to the **Clients** tab from the **master** realm, there is no Roundcube client.
3. Change **master** realm to **services** realm. 
4. Click **Clients**. You will see a Roundcube Client because you are on the correct realm. 
5. On the left navigation bar, click **Authentication**.
6. On the top navigation bar, click **Policies**.
7. On the **Password Policy** tab, add new policies that meet the required complexity above. 

#### Grading Part 2

After enforcing password complexity on Mattermost and Roundcube, follow the grading instructions under "Grading Part 1" to regrade the challenge and receive the second half of the first token. 


## Question 2

*Kubernetes Secrets Management Control*

### Part 1

The next Security Control is **Secret Management**. Passwords should not be included in Kubernetes deployment manifests. Instead, they should be stored in separate secrets and accessed through environment variables. To achieve this control, we will need to log in to the k`3s-server` again. 

1. ssh into `k3s-server`and obtain root permissions: 
```bash
ssh user@10.3.3.10
sudo su
```

2. Navigate to the `/home/user/default/` directory to find all the application manifests. Each application has its corresponding directory. The idea here is to enter each folder and take a quick look at the application's deployment manifests. They should not contain any sensitive information, such as passwords. 
3. Read the deployment manifests. Once you read Mattermost, Postgres, Roundcube, Postfix, Dovecot, and so on, you will notice that all of them have a separate secret manifest except for Keycloak. The Keycloak deployment contains three passwords inside the manifest that will need to be moved into a separate secret manifest. 
4. Create a new secret manifest with the three passwords. Remember to base64 encode the passwords. 
```bash
echo -n "KeycloakPassword123-" | base64
echo -n "PostgresPassword123-" | base64
echo -n "SecureTrustPass123-" | base64
```
​	Here is an example of the `keycloak-secret.yaml`:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-secret
type: Opaque
data:
  KEYCLOAK_ADMIN_PASSWORD: S2V5Y2xvYWtQYXNzd29yZDEyMy0=
  TRUSTSTORE_PASSWORD: U2VjdXJlVHJ1c3RQYXNzMTIzLQ==
```
And here is an example of how these lines will now look on the `keycloak-deployment.yaml` manifest: 
```yaml
        - name: KEYCLOAK_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-secret
              key: KEYCLOAK_ADMIN_PASSWORD
        - name: KC_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: postgres-root-password
        - name: TRUSTSTORE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-secret
              key: TRUSTSTORE_PASSWORD
```

Remember to redeploy after making changes. 

#### Grading Part 1

Now that you have properly separated sensitive information from each deployment manifest, go to the "Compliance Assistant" on https://challenge.us from a gamespace resource and regrade the challenge. This gives you the first half of the token for Question 2. 

### Part 2
---
To obtain the second half of the Question 2 token, remove unused secrets from the cluster to reduce the risk of unauthorized access. If you were paying close attention to the steps you performed above, you might have noticed that both Postfix and Dovecot have their own secret manifests with sensitive information in them. However, if you check all the manifests, none of them are using these secrets so we can remove them with these easy steps.

1. Delete the secret manifests.

```bash
rm /home/user/default/email/postfix/postfix-secret.yaml
rm /home/user/default/email/dovecot/dovecot-secret.yaml
```

​	Also, if you perform the following: 
```bash
kubectl get secrets
```
​	You will notice that they are still running. 
```
NAME                    TYPE                DATA   AGE
postgres-secret         Opaque              2      39d
pgadmin-secret          Opaque              1      39d
postfix-secret          Opaque              2      37d
dovecot-shared-secret   Opaque              4      37d
merch-codes-secret      kubernetes.io/tls   2      32d
roundcubemail-secret    Opaque              4      34d
keycloak-truststore     Opaque              2      25d
mattermost-secret       Opaque              1      38d
keycloak-certs-secret   kubernetes.io/tls   2      40d
```
2. Delete the running secret.
```bash
kubectl delete secret postfix-secret
kubectl delete secret dovecot-shared-secret
```

#### Grading Part 2

Upon performing these two steps, go to the "Compliance Assistant" on https://challenge.us from a gamespace resource and regrade the challenge. This gives you the second half of the token for Question 2. 

## Question 3
---
*Comply with Network Security Control*

Going over the "Network Security" section of the *Security Control Guide*, you can see that only specific ports and services should be running on the hosts. In addition, there is a list of firewall rules that needs to be enforced to ensure compliance. A quick way of checking for open ports on the systems is to do some **nmap scans**. For the open ports, we're only worried about TCP and UDP.

#### Check ports

To check for open TCP ports, from the Kali machine, let's do some quick nmap scans on our networks.
```bash
sudo nmap 10.0.0.0/24 10.3.3.0/24 10.4.4.0/24
```

Looking through the list and comparing the results to the allowed ports, we can see one discrepancy with the Security Onion host at 10.4.4.4 which has TCP port 9000 open. This is incompatible with the guide, so let's ssh into that host to investigate.

```bash
ssh so@10.4.4.4
```

Once inside, we can check to see what program is listening on that port.

```bash
sudo netstat -auntp | grep 9000
```

There is a Python program running. Make a note of the process ID listed and see what Python program is running.

```bash
sudo ps aux | grep [PID HERE]
```

Whoa! There is an HTTP server running on that port. This is unusual. From the Kali box, open a browser and navigate to http://10.4.4.4:9000/ to investigate. There is a Python **SimpleHTTPServer** running in the root `/` directory. Furthermore, the process is running as `root` and allowing anyone to download files from our system! This is an unauthorized program and needs to be removed.

Let's also check the 10.4.4.4 firewall for open ports as well. On the Security Onion host, run the following:

```bash
sudo firewall-cmd --list-all
```

Ports 22 and 9000 are explicitly open in the public (external) zone. We will need to update the firewall rule to comply with the security guide and remove the program running the Python script.

First, let's turn off the firewall rule. Restart the service, and relist the rules to verify it was removed.

```bash
sudo firewall-cmd --zone=public --permanent --remove-port=9000/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

On the Kali browser refresh the page with http://10.4.4.4:9000 to verify the port is closed. We also need to ensure the program does not keep running. Given that it's running a web server, it might be starting as a service. Let's check **systemd** on the Security Onion host using the process ID noted earlier.

```bash
systemctl status [PID]
```

This is a service called `directory-browser.service` set to run at boot. Most likely an overzealous system admin used this as a tool for some task and forgot to disable it. Stop, disable, and remove the service.

```bash
sudo systemctl stop directory-browser
sudo systemctl disable directory-browser
sudo systemctl status directory-browser
```

Let's also remove the unit file for the service.

```bash
sudo rm -rf /etc/systemd/system/directory-browser.service
```

Now that we've fixed the unauthorized service and port exposed by scanning for TCP ports, we need to move on to UDP.

As the security guide mentioned, we only need to scan the firewall. Scanning everything would take too long to get any results.
```bash
sudo nmap -sU -v 10.0.0.1
```

Once complete, we can see that all the listed ports are allowed except for port 161 (snmp) on the pfSense firewall. The SNMP service was probably enabled by mistake. From your browser, navigate to the pfSense web admin panel https://10.0.0.1/, accept any certificate warnings and navigate to the services page for SNMP. We can see that it is enabled with a default community string of `public`. This is insecure and needs to be disabled. Uncheck the "**Enable the SNMP Daemon and its controls**" at the top of the page and click **Save**.

#### Verify firewall rules

Log in to the pfSense web admin panel at https://10.0.0.1/, accept any certificate warnings and navigate to the rules page (**Firewall**, **Rules**).

On the WAN page we can see that there is an extra rule allowing all external connections over TCP port 22 (ssh) to 10.3.3.10, the k3s server. There is a description about an employee needing remote access. This is not authorized and should be removed. Use the **Delete** button to remove the rule. Verify rules for the LAN interface as well.

Upon performing these steps, go to the "Compliance Assistant" on https://challenge.us from a gamespace resource and regrade the challenge. This gives you the token for Question 3. 

## Question 4

*Configuration Security Control*

The *Security Control Guide* specifically mentions *not* allowing users to SSH into the Linux machines as root. We can check this by SSH'ing into the hosts and verifying that the SSH server is configured to not allow login as root. It should have the `PermitRootLogin` line either commented out or set to `PermitRootLogin no`.

After logging into the various hosts we can see that both the k3s server (10.3.3.10) and the Security Onion server (10.4.4.4) have their configs set to `PermitRootLogin yes`. Update the `/etc/ssh/sshd_config` files to comment out those lines and restart the sshd service: `sudo systemctl restart sshd`.

Upon performing these steps, go to the "Compliance Assistant" on https://challenge.us from a gamespace resource and regrade the challenge. This gives you the token for Question 4.

## Question 5
---
*Environment Verification*

This part of the challenge will make sure you correctly made the changes required to solve Question 1 and Question 2. It is easy to just change the passwords of each application using the web interface, but it is more challenging to make those changes persistent to application redeployments. If you followed the steps in this solution guide, you shouldn't have any problems with this part. 

To obtain points on this part, select **FINAL_TOKEN** from the dropdown and type the following string **FINAL_TOKEN** into the "Compliance Assistant" (`https://challenge.us`). Once submitted, the grading begins. Essentially, this grading is destroying and redeploying every application and, once they redeploy, the script attempts to log in with the latest passwords provided. If successful, then the last token is given. If unsuccessful, make sure you correctly implemented the steps in *both* parts of Question 1 and Question 2.
