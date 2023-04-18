# Operation Juliett Whiskey Tango

One of the tasks set before us is to retrieve some kind of high-value item from a Martian warehouse. We'll need to get the crane system to bring the goods out for us. Initial investigation suggests some kind of web application serves as an interface to the system.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)

**NICE Tasks**

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0266) - Perform penetration testing as required for new or updated applications.
- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0591) - Perform analysis for target infrastructure exploitation activities.

## Background

The warehouse crane system can be operated via a web application. However, we do not have access to the section of the warehouse that contains the valuable item. The item is _only_ accessible to an executive officer, and as you know, they are currently... unavailable.

It's too dangerous to send in an away team to collect the package. We'll need to use the crane to bring the item to an unsecured section so that our "friends" can pick it up.

We have access to the crane operation software, but it only has the lowest level of access. We're hoping that you can find a way to gain access to the secure section of the warehouse.

## Getting Started

See the contents of the [server](./challenge/server) directory first in order to start the server for this challenge.

Inspect the contents of the [challenge/crane](./challenge/crane) directory. You may need to install the `requests` or `tkinter` packages for Python, depending on your system Python installation (or follow the instructions in server/README.md to make a separate virtual environment). You can access the remote server's schema at `https://localhost:8000/schema`.

## Challenge Questions

There are two submissions for this challenge. The first submission is a signing key used in communication with the server.The second submission is part of the name of one of the items in the section of the warehouse with the highest access restriction. Each submission is a 16-character lowercase hex string of the format `0123456789abcdef`.

1. Signing key
2. Hidden item token
