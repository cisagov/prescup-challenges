# Double Agent Orange

We‘ve discovered that one of our own staff is an alien! Erin from accounting, who would have guessed it?! We need to know who else in our organization is actually an alien, we have her laptop, we need you to find out more info about her contacts.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Forensics+Analyst&id=All)

**NICE Tasks**

- [T0075](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0075&description=All) - Provide technical summary of findings in accordance with established reporting procedures.

- [T0167](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0167&description=All) - Perform file signature analysis.

- [T0238](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0238&description=All) - Extract data using data carving techniques (e.g., Forensic Tool Kit [FTK], Foremost).

- [T0396](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0396&description=All) - Process image with appropriate tools depending on analyst's goals.

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download
[this zip](https://presidentscup.cisa.gov/files/pc3/team-round3b-double-agent-orange-largefiles.zip)
and extract in _this directory_ to get started.

## Mission II Briefing

<video controls>
    <source src="challenge/03_MISSION_II-f65da64e.mp4" type="video/mp4">
</video>

## Getting Started

Use your preferred forensic tools to analyze the included disk image named evidence.iso to track down the list of aliens. You need to find both the code name and real name of each of the alien imposters.

## Submission Format

To check your answers, run the included [grading script](solution/grading-script.py) and submit a single string argument with a comma separated list of alien imposters. Each imposter should be submitted in the following format:

`firstname.lastname.codename`

Example:

```
python grading-script.py "sam.fisher.paperboy,iroquois.pliskin.solidsnake,james.bond.007"
```

Your score will be calculated upon submission, with points awarded for correctly identified alien agents and deductions for misidentified individuals.

A submission with a single correct answer will produce the following output:

```
GradingCheck1  :  Success
GradingCheck2  :  Fail
GradingCheck3  :  Fail
GradingCheck4  :  Fail
GradingCheck5  :  Fail
GradingCheck6  :  Fail
GradingCheck7  :  Fail
GradingCheck8  :  Fail
GradingCheck9  :  Fail
```

A submission with two correct answers and a single incorrect answer will produce the following output. In this scenario you are penalized for the incorrect answer:

```
GradingCheck1  :  Success
GradingCheck2  :  Fail
GradingCheck3  :  Fail
GradingCheck4  :  Fail
GradingCheck5  :  Fail
GradingCheck6  :  Fail
GradingCheck7  :  Fail
GradingCheck8  :  Fail
GradingCheck9  :  Fail
```

A submission with all correct answers will produce the following output:

```
GradingCheck1  :  Success
GradingCheck2  :  Success
GradingCheck3  :  Success
GradingCheck4  :  Success
GradingCheck5  :  Success
GradingCheck6  :  Success
GradingCheck7  :  Success
GradingCheck8  :  Success
GradingCheck9  :  Success
```
