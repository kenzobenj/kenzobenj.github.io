# MiningDropper

![](/images/miningdropper/Pasted%20image%2020260501195519.png)

MiningDropper, AKA BeatBanker, is an Android malware family that uses multiple stages of encrypted DEX and APK files loaded via native libraries. It serves two purposes: first, it downloads and executes a cryptocurrency miner, which it controls with Firebase messaging and monitors with a self-hosted Aptabase metrics server, and second it drops user-defined payloads - in this case BTMOB RAT. A recent MiningDropper campaign has been using trojanized versions of open-source applications for delivery. 

Contents:
* [Background](#background)
* [Stage 1](#stage-1)
* [Stage 2](#stage-2)
* [Stage 3](#stage-3)
* [Tracking Infrastructure](#tracking-infrastructure)
* [IOCs](#iocs)
* [References](#references)

## Background
I recently attended [Botconf](https://www.botconf.eu/) in France and it was an incredible conference! Every single talk was interesting and provided some sort of actionable insight, so I left with a massive list of new things to research. During the conference, I took a workshop on Android malware analysis:

![Android malware analysis workshop at Botconf](/images/miningdropper/Pasted%20image%2020260417220132.png)
*Android RE workshop at Botconf*

And Michele Roviello also gave a talk on tampering APKs to break analysis tools:

![Botconf talk on APK malformation](/images/miningdropper/Pasted%20image%2020260417220233.png)
*Botconf talk on intentionally malformed APKs*

This got me interested in checking out some Android malware, so I made a YARA rule based on one of the techniques from the talk:
```
rule apk_invalid_compression
{
  strings:
    $magic = {50 4b}
    $manifest = "AndroidManifest.xml"    
    $deflated = {08 00}
    $stored = {00 00}
  condition:
    $magic at 0 and $manifest and not ($deflated at 8 or $stored at 8)
}
```
This rule looks for APKs that have invalid compression types. Apparently, the Android loader will default to "stored" if it does not recognize the compression type, while some analysis tools will fail to unzip the APK. According to [PKWARE](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.6.TXT), stored means the files are not compressed:

![PKWARE definition of the "stored" type](/images/miningdropper/Pasted%20image%2020260417220607.png)
*PKWARE definition of the "stored" type*

## Sample: c038fb9ee8a4cb9cc1c7cb4b5383135380ac02ba040c00e97c100f697513d100

The sample is available on Malware Bazaar - [c038fb9ee8a4cb9cc1c7cb4b5383135380ac02ba040c00e97c100f697513d100](https://bazaar.abuse.ch/sample/c038fb9ee8a4cb9cc1c7cb4b5383135380ac02ba040c00e97c100f697513d100/).

At first glance, a couple of things stand out:

The package name and main activity package are different. This looks a little suspicious, plus that roommates package name sounds interesting; I expected lots of fake gambling and pirated streaming apps so I was curious to see what this lure entailed.

![Package information for the sample](/images/miningdropper/Pasted%20image%2020260417221144.png)
*Package mismatch*

It also requests commonly abused permissions for installing malicious payloads, keeping malware services alive, and detecting antivirus and other unwanted programs:
 
![APK permissions](/images/miningdropper/Pasted%20image%2020260417221353.png)
*Suspicious permissions*

It turns out this roommates app is some [open-source app](https://github.com/mattieapps/roommates-android) that hasn't been updated in eleven years. Seems like a random thing to pick up and add a backdoor to, but I guess it saves time if it's a nice, functional app ¯\\_(ツ)_/¯

## Stage 1

The manifest contains references to classes that are not present in the APK, so this is immediately suspicious.

![Missing classes declared in the manifest](/images/miningdropper/Pasted%20image%2020260423115056.png)
*Missing classes referenced in the manifest*

The APK includes a native library file `libstriolateserviceberryinitiary.so`, so it's possible that this library handles loading additional classes. The main package references native code in four places, so the next step will be to analyze those functions in the native library.

![Native functions in the APK](/images/miningdropper/Pasted%20image%2020260423114436.png)
*There are four native functions in the APK*

#### libstriolateserviceberryinitiary.so

The strings are obfuscated by long sequences of single-byte XORs:

![XOR string decryption](/images/miningdropper/Pasted%20image%2020260418081737.png) 
*XOR-encrypted strings*

I wrote a [Binary Ninja script](https://github.com/kenzobenj/RE-Scripts/blob/main/MiningDropper/jni_binaryninja.h) to decrypt and patch the strings; it misses a couple edge cases where the HLIL interpreted the data references as indexes into an array, but it does enough to get the idea. I also used ChatGPT to modify the [JNI header file from Jinmo](https://github.com/Jinmo/headers/blob/master/jni.h) so that it is compatible with Binary Ninja - [found here](https://github.com/kenzobenj/RE-Scripts/blob/main/MiningDropper/jni_binaryninja.h). 
After running the string decryptor and applying the proper types from the header file, the code is a bit easier to follow. For the JNI functions, the first argument will always be a pointer to the `JNIEnv` and the second argument will always be `this`, as seen below.

![JNI function signature](/images/miningdropper/Pasted%20image%2020260423210730.png)
*Typical JNI function signature*

The function shown above is invoked in the `onCreate` method of the `RoomMatesApplication` class, so it is the first native function to run. It carries out some anti-analysis checks and then decrypts and executes additional stages.
##### Anti-Analysis 
The anti-analysis checks include typical device information checks like the system architecture and device model as well as registering a `SensorEventListener` that listens for 300ms and tracks accelerometer changes. The listener keeps track of X, Y, and Z values in a float array and calculates the change in these values during the listening period. If any of the axes values changes by at least 0.01 m/s², then the check passes. All of the logic for this also resides in the native library.

![SensorEventListener class](/images/miningdropper/Pasted%20image%2020260428190631.png)
*SensorEventListener with native functions*

##### Loading Additional Classes
After the anti-analysis checks, the function XOR-decrypts an asset called `zgj97naaskbtvnvs ` with key `fxkjxrvn4acpkjflfynkmgdbmcf4kxdawglgbionovmbxicxcdlpvpm3sedug8wb` and then loads it as a DEX file using `InMemoryDexClassLoader`.

![Loading the encrypted asset](/images/miningdropper/Pasted%20image%2020260423211348.png)
*Opening the encrypted asset*
![The XOR key](/images/miningdropper/Pasted%20image%2020260423211602.png)
*Hardcoded XOR key*
![XOR decrypting the asset](/images/miningdropper/Pasted%20image%2020260423212104.png)
*XOR decryption*

The code then loads the `com.example.virusscanbypassbootstrapper.DexLoader` class from the decrypted DEX file and resolves the `loadDex` method from the class.

![Resolving the DexLoader class](/images/miningdropper/Pasted%20image%2020260423213522.png)
*Resolving the loadDex method*

Then, it invokes `loadDex`, passing in another asset name, `6hcooib2cq5kli1s/gwfxcb3b`, as the argument. The method `loadDex` decrypts the given asset with AES using the first 16 bytes of the SHA1 hash of the file name as the key and null bytes as the IV. In all further references to decryption, assume that this is the same scheme, although some files have "1" appended to the name before calculating the hash.

![Asset decryption within the DexLoader](/images/miningdropper/Pasted%20image%2020260423220216.png)
*Using AES to decrypt assets*


The decrypted file is another APK and it contains the missing classes that were listed in the original APK's manifest.

![The missing package from the original manifest](/images/miningdropper/Pasted%20image%2020260423221623.png)
*The missing package that we saw in the original manifest*

After this next stage is loaded, the native library loads the `com.tx.wartracedahlia.App` class and invokes the `externalInit` function. 
Finally, it uses the `setComponentEnabledSetting` method of the Android class `PackageManager` to enable `com.tx.wartracedahlia.Psychosome`, which is a `BroadCastReceiver` in the second decrypted payload.

## Stage 2
The APK that the native code decrypted and loaded from `6hcooib2cq5kli1s/gwfxcb3b`  contains the core malicious functionality of the dropper, including executing and monitoring a crypto miner and dropping additional payloads.
This stage uses [Aptabase](https://github.com/aptabase), an open-source analytics library, to send mining metrics and device information to a self-hosted ingestion URL. The code is very similar to [aptabase-kotlin](https://github.com/aptabase/aptabase-kotlin/blob/22548b921f6fb696e6aa90b594cce4cb34551f72/aptabase/src/main/java/com/aptabase/Aptabase.kt#L71-L82), but the hardcoded SDK version is `aptabase-java@0.0.8`, which is interesting because I cannot find any references to aptabase-java online and it is not a repo under the Aptabase account in Github. It seems like the developers of MineDropper may have made their own Java-based version of the SDK for some reason.

![Out-of-the-box metadata added to Aptabase messages](/images/miningdropper/Pasted%20image%2020260425220418.png)
*Default metadata reported by the aptabase-java library*

The sample uses the app key `A-SH-2395115531` and a self-hosted ingestion URL `hxxps://aptabase.jesfeoqrj3[.]xyz:8443`. It reports:
* App liveliness (based on if battery optimization is ignored)
* Successful miner installation
* Miner uptime
* Successful payload installation
* Phone temperature and flag if it is overheated
* App installation time

The native code loads the class `com.tx.wartracedahlia.App` and invokes its `externalInit` function. This function reports the installation time to the Aptabase server, initializes a Firebase client, and decrypts and executes the third stage loader.

![externalInit function](/images/miningdropper/Pasted%20image%2020260426203826.png)
*externalInit method*

`com.tx.wartracedahlia.Psychosome` is also registered as a `BroadCastReceiver` by the native library, as well as in the application's manifest. This receiver listens for `BOOT_COMPLETED` events, which trigger when the device has finished booting and the user has unlocked the device.

![Intent filter for the BroadCastReceiver](/images/miningdropper/Pasted%20image%2020260424120923.png)
*The Psychosome class listens for BOOT_COMPLETED intents*

When triggered (e.g. every initial unlock after reboot), it starts a service that:
* Displays a fake Google Play screen prompting the user to update the app. This gets the user to grant the app permission to install additional APKs.
* Generates a fake system update notification telling the user to keep the phone on
* Plays a looping inaudible MP3 file to prevent the service from being killed
* Registers a wake lock to prevent the CPU from sleeping
* Downloads and executes an XMRig binary (cryptocurrency mining program)

![BroadCastReceiver onStart method](/images/miningdropper/Pasted%20image%2020260426135934.png)
*Psychosome onStart executes the fake update notification, MP3 keepalive, and crypto miner*

The XMRig binary is downloaded from one of five hardcoded base URLs. In this case, only one URL is configured and the rest are placeholders of the format `https://www.backupdomain2026xxx00<index>`. Below is a screenshot of the decrypted strings:

![Decrypted base URLs](/images/miningdropper/Pasted%20image%2020260426123029.png)
*Decrypted URLs configured for the miner download*

The downloaded file is decrypted and saved to a new file called `d-miner`

When preparing the command line for the miner process, it first tests a direct connection to a hardcoded mining pool URL. If that fails, it falls back to a proxy URL hosted on the same domain. The arguments passed in the command line are `-o <pool> -k --tls --no-color --nicehash`.

![Building the XMRig command line](/images/miningdropper/Pasted%20image%2020260426115809.png)
*Building the XMRig command line*

## Stage 3
Similar to the previous stage, an asset, this time a ZIP file named `ouds`, is decrypted. The ZIP file contains an encrypted DEX file and two native libraries.

![Third stage files](/images/miningdropper/Pasted%20image%2020260426203521.png)
*Stage 3 DEX and native libraries*

The malware decrypts and loads the DEX file and then resolves the `com.google.installerlibrary.SplitApkInstaller.installApkPublic` method. After resolving the method, it invokes it twice, first to install a miner payload and then to install what is calls a "user" payload. The below screenshot shows the asset names and payload types that are passed to the method as arguments:

![Names of the miner and user assets](/images/miningdropper/Pasted%20image%2020260426205038.png)
*Config file names for the miner and user payloads*

I didn't look too closely at the internal workings of the third stage loader. The class that is invoked is called `SplitApkInstaller`, so presumably it concatenates multiple files into an APK and loads it. The files that are passed to the native function as arguments (see the above screenshot) are encrypted configuration files. The `splits` property provides the asset names that need to be combined for the final payload. Each of those file pieces are also decrypted before concatenating the results.

Miner config:
```
{"isRemoteControl": false, "isTestKeyEnabled": false, "splits": ["dimensum"], "subscriptionEndMillis": 4611686018427387903, "messageAuthenticationCode": "eVAmHju3UqrVWR56gOMaUQ==", "simpleInstaller": "deprecated"}
```

User config:
```
{"isRemoteControl": true, "isTestKeyEnabled": false, "splits": ["tainosemihardness", "quintuplesquarrosely", "hoochinoo"], "subscriptionEndMillis": 1777901939986, "messageAuthenticationCode": "edeAe6usV2MbTHYNQdqs4A==", "simpleInstaller": "deprecated"}
```

The developer left a friendly message in the `SplitApkInstaller` class :)

![Message from the loader developer](/images/miningdropper/Pasted%20image%2020260426201147.png)
*Words of encouragement*

#### Miner (Again)
The miner payload is the `dimensum` asset, which is an encrypted APK file. The manifest declares a number of services that are not present in the APK:

![Services defined in stage 3's manifest](/images/miningdropper/Pasted%20image%2020260427202305.png)
*Services declared in the manifest*
 
 This APK uses the same loader mechanism as the initial stage. The native library `liblwvgttkvjmh.so` uses a hardcoded XOR key `a71k3kDED5iwxW08fZJFVAhZ8T2p8vnSd2Vrr3TYqSxVMQR2Gqvh3pA8q7glsHZy` to decrypt and load yet another DEX file `nGnIPZFP9UKMHdD5`. This file has the `com.example.virusscanbypassbootstrapper.DexLoader` class that then decrypts and loads `rpC2MwWa1KAcl7e6/VPTvdXBt`, which contains the missing classes. This time, the native library does not use string encryption, so the encrypted DEX file name and XOR key can be pulled from the strings.
 
![Assets used to load the stage 3 miner service](/images/miningdropper/Pasted%20image%2020260427202540.png)
*Assets used to load the miner service*

A lot of the code in this payload is duplicated from the second stage - it uses the same MP3 file audio loop and wake lock keepalive, same Firebase configuration, same XMRig download and execution, and same Aptabase metrics reporting for the miner. It seems like this serves as a separate, external mining service for additional stealth and resiliency. Stage 2 binds to this external service and communicates using [Messenger](https://developer.android.com/reference/android/os/Messenger) for IPC. This channel is used to wake up the external service and have it subscribe to Firebase topics for commands. The mining is started and stopped based on messages received via Firebase. 

![Service binding in stage 2 for IPC to stage 3](/images/miningdropper/Pasted%20image%2020260429205921.png)
*Stage 2 service binding and IPC wakeup functions targeting stage 3*

![IPC handling in stage 3 mining service](/images/miningdropper/Pasted%20image%2020260429210118.png)
*Stage 3 handler for the IPC messages*

#### BTMOB RAT

The payload labeled "user" is a BTMOB RAT sample. This is a fully featured implant and could be a whole blog post on its own, so I did not do a deep analysis on it. Decrypting some of the strings, it looks like this is version `BT-v3.4.1` and the C2 address, or at least one of them, is `190.102.43[.]43`. HTTP requests are made to this address with the path `/yaarsa/private/`, for example one such request is made to `/yaarsa/private/log_error.php`.

## Tracking Infrastructure
All of the related infrastructure I have observed uses a Let's Encrypt certificate with a CN for an `aptabase` subdomain. The shodan query `ssl.cert.subject.cn:aptabase` currently returns six results, three of which are definitely C2 domains for MiningDropper. Two more found on VirusTotal, `aptabase.khwdji319.xyz` and `aptabase.fud2026.xyz`, show that the operators seem to like the .xyz TLD. It looks like a domain-generation algorithm might be in use based on `jesfeoqrj3.xyz` and `khwdji319.xyz`.

## IOCs

### Network & Other IOCs:

| Indicator                                                                 | Description                                                |
| ------------------------------------------------------------------------- | ---------------------------------------------------------- |
| A-SH-2395115531                                                           | Aptabase app key                                           |
| hxxps://aptabase.jesfeoqrj3[.]xyz:8443                                    | Self-hosted Aptabase server                                |
| hxxps://aptabase.jesfeoqrj3[.]xyz/libmine-arm64.so                        | Download URL for 64-bit miner                              |
| hxxps://aptabase.jesfeoqrj3[.]xyz/libmine-armeabi-v7a                     | Download URL for 32-bit miner                              |
| hxxps://white-thunder-bef3.botmaster512.workers[.]dev/libmine-armeabi-v7a | Redirect when attempting to download the 32-bit miner      |
| pool.jesfeoqrj3[.]xyz                                                     | Mining pool direct connect address                         |
| pool-proxy.jesfeoqrj3.xyz:8443                                            | Mining pool proxy address                                  |
| 1:39848184100:android:c44d4f602ecf40683bcbb1                              | Firebase application ID                                    |
| AIzaSyDDRPszQIVKnbIBw9nZuuhferi4-I0xwXU                                   | Firebase API key                                           |
| waking-21b04.firebasestorage.app                                          | Firebase storage URL                                       |
| 190.102.43[.]43                                                           | BTMob C2                                                   |
| aptabase.fud2026[.]com                                                    | Additional MiningDropper domain from infrastructure pivots |
| aptabase.uasecurity[.]org                                                 | Additional MiningDropper domain from infrastructure pivots |
| aptabase.khwdji319[.]xyz                                                  | Additional MiningDropper domain from infrastructure pivots |
| aptabase.fud2026[.]xyz                                                    | Additional MiningDropper domain from infrastructure pivots |
| 207.90.195[.]25                                                           | IP hosting the fud2026 and uasecurity domains              |
| 147.93.153[.]119                                                          | IP hosting the jesfeoqrj3 domain                           |

### Package & Class Names:

| Name | Description |
|-----------|--------------|
|com.lsi.kidroncounterdisengage | Mining service package name |
| com.components.ExternalForegroundConnectorService | Mining component service class name |
| com.components.ExternalLauncher | Mining component activity class name |
|com.google.installerlibrary.SplitApkInstaller| Third stage installer class |

### Files:

| SHA256                                                           | Description                                                                   |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| c038fb9ee8a4cb9cc1c7cb4b5383135380ac02ba040c00e97c100f697513d100 | Initial APK - trojanized open-source application                              |
| e0d4cfb63514f01f227a82f22d60da1c40424ae7088c04b11aa63e0ca3084abb | `libstriolateserviceberryinitiary.so` - the native library in the initial APK |
| 58e39152786a0f48dd005e4189769be9e0c2e2d0067c8128252d91ae85559117 | Dex file containing the loader executed by the native library                 |
| e69c99bc3ddce0217489466a0a73e99e684c013a7ff3aa347359465541753e96 | The second stage DEX                                                          |
| e97609e2fe4e2cfae7acc2e73ee7faf59e4a06b57a2abc890c98af97586bbe65 | XMRig payload                                                                 |
| 7e116a48e9862018ac4e3c105ac88f05ff0e06a573fa76dd91680884ab4f3b14 | Stage 3 external miner service                                                |

## References:

* [https://securelist.com/beatbanker-miner-and-banker/119121/](https://securelist.com/beatbanker-miner-and-banker/119121/)
* [https://cyble.com/blog/miningdropper-global-modular-android-malware/](https://cyble.com/blog/miningdropper-global-modular-android-malware/)
* [https://web.archive.org/web/20250920032410/https://sandbox.qianxin.com/blog/2025/04/29/tq-sandbox-MAUI-sample-analysis/#%E5%8A%A8%E6%80%81%E5%88%86%E6%9E%90](https://web.archive.org/web/20250920032410/https://sandbox.qianxin.com/blog/2025/04/29/tq-sandbox-MAUI-sample-analysis/#%E5%8A%A8%E6%80%81%E5%88%86%E6%9E%90)








