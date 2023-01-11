# Ancient Ruins

## Background

We recovered an alien Seelax droid, which appears to be some kind of cleaning robot. It was partially destroyed, but the motherboard is operational. Two out of three hard drives could be imaged.

## Getting Started

The `seelax-droid` VM is a representation of the operational motherboard, and an attached CD-ROM image contains the two recovered hard drive images,
obviously missing the unrecoverable third drive image.

The machine appears to run a daemon (`seelax.service`) listening on `TCP 31337`, where it runs some kind of request/response protocol. It throws error messages likely due to its inability to access to the missing disk.

This machine contains (or is otherwise able to access) the `EncryptedCodexC` string needed to complete the overall challenge.
