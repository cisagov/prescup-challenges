# Waiting for Harry

Sometimes, the easiest path to someone's secrets is through their heart. 

<!-- TODO: Update this with the relevant roles -->
**NICE Work Roles**
- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

For more information on these roles, please visit: https://niccs.cisa.gov/workforce-development/nice-framework


<!-- TODO: Update this with relevant tasks -->
**NICE Tasks**
- [T0280](https://niccs.cisa.gov/tools/nice-framework): Identify and validate vulnerabilities in the system	
- [T0653](https://niccs.cisa.gov/tools/nice-framework): Identify and recommend methods for exploiting target systems	
- [T0269](https://niccs.cisa.gov/tools/nice-framework): Conduct exploitation of targets using identified vulnerabilities	
- [T0650](https://niccs.cisa.gov/tools/nice-framework): Conduct target and technical analysis of systems and vulnerabilities

## Background

Harry is a very boring, predictable company man. He gets up everyday, brushes his teeth, eats his meals, 
checks the leaderboard for his favorite game, goes to work, comes home, eats dinner, and goes to bed. 

He has also unwittingly collected sensitive information that you must retrieve from the cookie jar in his browser. 

Here's what we know, Harry checks the leaderboard for his favorite game Dodge the Creeps extremely regularly. 
So, if we can take advantage of this game, we might have a way to extract the information.

## Getting Started

| Site | Link |
| --- | --- |
| Game | `https://dodgethecreeps` |
| Leaderboard | `https://dodgethecreeps/leaderboard` |
| `gdsdecomp` | `https://dodgethecreeps/tools/gdre_tools_linux_x86_64.zip` |
| Listener | `https://listener` |

We've set up a proxy to the leaderboard, game, gdsdecomp (a godot PCK decompiler), and a listener service, which you may find helpful. 
The Leaderboard and Game are where Harry spends most of his time apart from working. 
Once you figure out how to take advantage of the sites where Harry spends the most time, use the listener 
service to exfiltrate the data. This listener will respond with a 404 to any request other than logs and 
save the request to an internal data store which you can access using `http://listener/logs`. 

