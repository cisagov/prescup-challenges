# Return Rodeo
_Challenge Artifacts_

- `validate_string`: vulnerable binary with `setuid-root` on the `server`
  - NOTE: this binary should be installed on a standard ubuntu or kali server
    as `/usr/sbin/validate_string`, and can then be exploited into displaying
    the contents of arbitrary files under `/etc/`, or to gain a root shell on
    the `server`.

