# Now This is Pod Racing

Time to test those exploitation skills. Complete the given tasks and win the flags along the way!

**NICE Work Role**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/): Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0572](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply cyber collection, environment preparation and engagement expertise to enable new exploitation and/or continued collection operations, or in support of customer requirements.

## IMPORTANT
This challenge is only partially open sourced. The files in the [challenge directory](./challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

Our analysts have spent months gathering intel about the Aurellian spaceship's network topology. It looks like most of their spaceship networks are quite similar. Thanks to the gathered intel, we managed to build an environment where you can hone your exploitation skills for future missions. We have assigned you three tasks. Upon completing a task, you are awarded with a flag and new Kubernetes configuration file.

## Getting Started

1. From your Kali VM, browse to `challenge.us/files` and download `landingspace.kubeconfig`. You need this to access the first namespace on the node, ` landingspace`.
2. Download `kubectl` and `docker.io` to prepare your environment.
3. Intel tells us the registry used to push/pull Docker images is: `registry.merch.codes:5000`.

### First Task

The initial pod, named `firstpod`, has problems starting. Discover what is wrong and find a way to fix it. Make sure to keep notes as you go. 

### Second Task

After completing the first task, you should have gathered enough files to stand up a pre-existing email server. However, you don't have the credentials to any of the email accounts. Reset the password of the `superadmin` user and gain access to these email accounts. Don't delete any user email accounts or sent emails -- you'll need them.

### Third Task

After completing the second task, you have the final Kubernetes config. The final step to get root access to the Kubernetes cluster. The final flag is in `/root/flag`.

Good luck! 

## Challenge Questions

1. Get the first flag after fixing the pod within the namespace "landingspace".
2. After standing up the email server, resetting the superadmin user credentials and obtaining access to the email accounts, retrieve the second flag.
3. Obtain root access to the Kubernetes cluster to retrieve the final flag under /root/flag.