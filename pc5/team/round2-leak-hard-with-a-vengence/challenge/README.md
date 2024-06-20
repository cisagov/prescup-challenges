# Leak Hard with a Vengeance

_Challenge Artifacts_

postgres-database-server database scripts
- [insert_users.sql](./postgres-database-server/insert_users.sql) - Script to add users to database.
- [insert_files.sql](./postgres-database-server/insert_files.sql) - Script to add files to database.
- [pga_job.sql](./postgres-database-server/pga_job.sql) - Script to pgagent jobs.
- [pga_jobstep.sql](./postgres-database-server/pga_jobstep.sql) - Script to add pgagent job steps.
- [pga_schedule.sql](./postgres-database-server/pga_schedule.sql) - Script to schedule pgagent jobs.
- [startup.sh](./postgres-database-server/startup.sh) - Startup script to execute pgagent.

file-server scripts
- [554edf00.cfg](./file-server/554edf00.cfg) - Data file read by [cfgscr](./file-server/cfgscr).
- [dd31aff5.cfg](./file-server/dd31aff5.cfg) - Data file read by [cfgscr](./file-server/cfgscr).
- [cfgscr](./file-server/cfgscr) - Script that makes the calls to read file data and send it out via dig calls to DNS.server.

dmz-server scripts
- [website.py](./dmz-server/website.py) - Script to execute in order to start website. Requires all other files in folder to run.

dmz-user scripts
- [listener.py](./dmz-user/listener.py) - Script to start listener to receive data from dmz-server website.

user-mail scripts
- [startup.py](./user-mail/startup.py) - Script to begin exfiltrating financial data via email.
