# Kill the Red Paladin

Assess, reverse engineer, and find the locus of an apparent Win10 workstation compromise.

**NICE Work Roles:**
- [Cyber Defense Infrastructure Support Specialist](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**
- [T0042](https://niccs.cisa.gov/workforce-development/nice-framework) for specialized cyber defense applications.
- [T0261](https://niccs.cisa.gov/workforce-development/nice-framework) - Assist in identifying, prioritizing, and coordinating the protection of critical cyber defense infrastructure and key resources.
- [T0348](https://niccs.cisa.gov/workforce-development/nice-framework) - Assist in assessing the impact of implementing and sustaining a dedicated cyber defense infrastructure.
- [T0483](https://niccs.cisa.gov/workforce-development/nice-framework).


## IMPORTANT

There are no downloadable artifacts for this challenge. The full challenge can be completed on the hosted site.

## Background
"Hey, it's Betty! I know you are busy, but my work computer has been acting strange, and I was thinking you might be able to fix it. I think it all started when we began playing G&G. I was researching that story you told me about, and I couldn't help it, I was reading about it during breaks at work. It's so cool! But yeah, I login to my computer and a few minutes later it starts doing weird things. I can't get a virus just by searching up information can I?
By the way, what card did you draw for our next quest?"

You will need to assess, reverse engineer, and find the locus of an apparent workstation compromise. Afterwards, you'll need to answer Betty's questions about what precisely happened.

## Getting Started
Login to the provided Win10 user workstation in order to get started. All of the tools necessary to correctly answer the questions have already been provided on the machine.

## Example Submission

There are four questions in this challenge. Each is worth 25% of the total.

**Part 1/4** - What is the domain that the malware found on Betty's computer is using for DNS to get to its C2?
```
malware.domain
```

**Part 2/4** - What is the EDNS client subnet returned as part of the body in these DNS queries?
```
1.2.3.0/24
```

**Part 3/4** - Relevant to that DNS query, what is the version number of the server software currently running?
```
4.7.2
```

**Part 4/4** - Can you force that dns software to reveal an error code? What is that error hash code?
```
b92ca87d
```
