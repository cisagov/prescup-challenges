# Pipeline

You have made your way into an enemy agency's DevOps network. Compromise their ops stations with our agency's custom backdoor and gain access to their fileserver to analyze their ransomware.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework/)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework/)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework/): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework/): Identify vulnerabilities

## Background

You belong to a spy agency and have found ssh credentials to a server belonging to an enemy agency's organization. Use the credentials to access the sshserver. Then exploit the agency's CI/CD and automation technologies to work your way deeper into the network and install your agency's custom backdoor on the enemy ops stations. Finally, gain access to their fileserver and extract their malware for further analysis.

## Getting Started

- Use the provided kali machine to login to the `sshserver` with the following creds `user1:password1`.
- Examine the `sshserver` to make your way deeper into the network.
- Browse to `http://grader` to download `custom_backdoor` and run the grader check when necessary.
  - `custom_backdoor` can be used to open a bind shell on `port 4444`. This bind shell can be accessed via a simple `nc` connection.
  - `grader` can be accessed from both the `kali` network and the internal network accessible from `sshserver`.
- `/home/user/tf-go-mod/go.mod` is a go module with terraform libraries pre-installed. 
  - Building with this mod will result in a go binary called `tf-go`.

## Tokens

- Token 1: Survey the `sshserver` for useful information.
- Token 2: Compromise the `CI/CD` pipeline to escalate your privileges.
- Token 3: Take advantage of the `infra runner (controller)` to extend your access deeper into the network.
  - The token will be in `/tmp/token3.txt` on the `infra runner`.
- Token 4: The `ansibleadm` user periodically runs ansible tasks. Use these tasks to deploy and execute the `custom_backdoor` on managed nodes.
  - **Important**: Once you have executed `custom_backdoor` on the managed nodes, run the grader check at `http://grader`. Do not modify or remove any pre-existing Ansible tasks. Only append your changes, or the grader check will fail.
- Token 5: Gain access to the `fileserver` and extract the `xcryptzor` binary. Analyze the file to find the token.  


## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali|user|password|
|sshserver|user1|password1|
|`http://grader`|N/A|N/A|
