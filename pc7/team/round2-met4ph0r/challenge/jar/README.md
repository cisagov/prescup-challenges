# Building:

```bash
javac VulnJar.java
jar cvfm scott_patch.jar manifest.txt VulnJar.class
```

JAR file is copied @ `/ctf/scott_patch.jar` and moved to `/ctf/wiki/images/scott_patch.jar` during init.
