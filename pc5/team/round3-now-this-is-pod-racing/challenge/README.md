# Now This is Pod Racing 

Challenge Artifacts 

## IMPORTANT
This challenge is only partially open sourced. Using the files in this directory, as well as a system running Kubernetes, you can recreate this challenge on your own. The full challenge in its original form can be completed on the hosted site. 

### Context Config: 
- [landingspace.kubeconfig](./contextConfig/landingspace.kubeconfig) --- A configuration file initially provided to competitors to help them access the first namespace `landingspace`. 
- [landingspace-rbac.yaml](./contextConfig/landingspace-rbac.yaml) --- A configuration file providing the RBAC configurations for the `landingspace-k3s` context. 
- [secondspace.kubeconfig](./contextConfig/secondspace.kubeconfig) --- A configuration file provided to competitors after they have successfully accessed `firstpod`. It is used to access `secondspace`.
- [secondspace-rbac.yaml](./contextConfig/secondspace-rbac.yaml) --- A configuration file providing the RBAC configurations for the `secondspace-k3s` context. 
- [finalspace.kubeconfig](./contextConfig/finalspace.kubeconfig) --- A configuration file to access the `finalspac3` namespace. 
- [finalspace-rbac.yaml](./contextConfig/finalspace-rbac.yaml) --- A configuration file providing the RBAC configurations for the `finalspace-k3s` context. 

### Firstpod: 
- [firstpod.yaml](./firstpod/firstpod.yaml) --- An export of the configuration of `firstpod` taken from the hosted environment. Keep in mind when recreating that the pod was intentionally "broken" in the challenge and needed to be corrected to move on to the next phase of the challenge. . 

- [secondspace-files](./firstpod/secondspace-files/) --- Contains `.kubeconfig` and `.yaml` files that were mounted and accessible through `firstpod`. They are used to access and deploy applications in `secondspace` and progress to the next phase of the challenge. 

### Secondspace: 
- [postgresPod](./secondspace/postgresPod/) --- Directory that contains configuration files for creating the `postgres` pod in `secondspace`. It contains the files: `postgres-configmap.yaml`, `postgres-deploy.yaml`, `postgres-secrets.yaml`, and `postgres-service.yaml`. 
- [db-backup.zip](./secondspace/db-backup.zip) --- A compressed directory which contains database backups taken from the hosted environment of the databases present on the `postgres` pod. 