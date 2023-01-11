# It, like, stopped working?

_Setup_

1. Set up an ubuntu VM

2. Ensure the `/usr/share/prescup` directory exists, containing the following
   files:

   - `pc4ncfbk.sh`
   - `pc4repo.sh`

3. Start both scripts as permanently running services:

```bash
/usr/bin/ncat -l -k -m1 -c /usr/share/prescup/pc4ncfbk.sh
/usr/share/prescup/pc4repo.sh
```
