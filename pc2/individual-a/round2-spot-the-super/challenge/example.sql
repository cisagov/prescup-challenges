-- Copyright 2022 Carnegie Mellon University.
-- Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
-- root or contact permission@sei.cmu.edu for full terms.

select rolname,rolsuper,rolcanlogin FROM pg_roles;
CREATE USER foo PASSWORD 'bar';
create user abc superuser password 'xyz';
