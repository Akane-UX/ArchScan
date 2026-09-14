# ArchScan

Heads up: this is just a personal side project I hacked together for myself. It ain't some hardcore enterprise security tool, so don't treat it like one. It's basically a lightweight multithreaded scanner to dig through the system and catch sketchy stuff in shell scripts (.sh, .bash, etc.) and Arch AUR PKGBUILDs.

## How to roll with it

First off, make sure you got the dependencies sorted out:
```bash
pip install -r requirements.txt
```

If you wanna scan your entire rig (might take a minute but it skips the noisy system folders):
```bash
python archscan.py /
```

If you just wanna check a specific folder, like your home dir:
```bash
python archscan.py ~/
```

Or if you got a single sketchy file you wanna inspect real quick:
```bash
python archscan.py ./that-weird-script.sh
```
