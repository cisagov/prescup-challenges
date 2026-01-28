# Lab Artifacts

List of artifacts and their descriptions/use

 - [juiceshop-sbom.json](./juiceshop-sbom.json) - The SBOM file for juiceshop, hosted by CycloneDX at https://github.com/CycloneDX/bom-examples/tree/master/SBOM.
 - [xz-5.6.1.tar.gz](./xz-5.6.1.tar.gz- The full vulnerable package containing XZ Utils v5.6.1. This can be used to statically create an SBOM file, but should not be installed.
 - [xz.json](./xz.json) - A copy of the .json formatted SBOM created from the safe version of XZ Utils.
 - xzbot - Not included, but can be retrieved from `amlweems`' GitHub project at https://github.com/amlweems/xzbot. 
   - `xzbot` is used to perform the exploit in the lab, however, the version used in the lab was altered to use a custom public/private key.
 