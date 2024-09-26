# Android Application Analysis

_Challenge Artifacts_

 - [AndroidProtektorAPI](./AndroidProtektorAPI/) - Source code for the API  
   - You can build this app using the following command: `dotnet build --configuration release`

challenge-server
 - [.apk file](./challenge-server/com.companyname.androidprotektor.apk) - This file gets copied to the kali box by the startup script.
 - [startupScript.sh](./startupScript.sh) - This startup script runs to configure the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge. 
 - [imgs](./challenge-server/imgs/) - Image files copied to the Kali VM by the startup script.
   
kali
 - [APK Competitor Source Code](./kali/AndroidProtektor_Competitor/) - This code is provided to the competitor for the challenge.
 - [APK Complete Source Code](./kali/AndroidProtektor_Complete/) - This is the complete source code for building the APK in Visual Studio 2022.
 - [README.txt](./kali/README.txt) - This file is located on the desktop of the Kali VM.

