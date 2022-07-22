# The Lich's Phylactery Solution

### Step 0: Identify files in play

There are only a few relevant files to separate from the chaff:

- `_diaryofamadman.txt` which provides hints to what has happened.

- `bin/phylactery` binaries. I've provided one for most systems, but the one that runs on Kali is `bin/phylactery_darwin_amd64`. This binary does the actual splitting and binding of files.

- `_magic_jar.sqlite` database. Here the player will find the encrypted files we need to assess. Their particular directory structure is also indicated.

- `bin/phylactery` you'll need the correct distribution binary for your machine.

### Step 1: Add phylactery binary to bin

I typically cheat and just `cp phylactery_linux_amd64 /usr/bin/phylactery` for a kali box.
You should be able to just run `phylactery` from the \$ prompt and see the help text for constructing a command

### Step 2: Extract files from database

FLAG1: `select \* from hints;` will uncover the only partial flag available along the way.

- Player will need to script file out to the filesystem and write them by their `group_id` within the database, and use their `o_id` as the file name.

  `SELECT o_id, group_id, data FROM documents;`

- For each row, we'll need to put the files in their proper directory structure indicated in the group_id column.

- We end up with a temp directory of these written files from the sqlite database.

### Step 3: Bind the files back into their original state

- The binding of the original file we do using the Phylactery binary. The easiest way to use this is to add it to `/usr/bin/` so that from the command line in any directory, we can just call it by name and perform the binding.

- But! Each file has been split 4 times, so we must use the phylactery binary to bind the files back together, AND put them in a reverse roll-up tree. Doing this four times results in the flag file. This looks like:

  - Bind 8 files to form 1 resultant file

  - Take original 8 out of play by deleting or moving them somewhere else

  - Move resultant files from 8 children up one directory, forming a new directory of 8 phylactery files

  - Loop through this until we arrive back to 1 original file.

### Solution file

   [solution script](./solution.py)
