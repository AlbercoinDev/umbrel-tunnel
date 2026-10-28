"""Exercise SSH argument transport without connecting to or modifying a VPS."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class PushScriptTests(unittest.TestCase):
    def test_installer_arguments_survive_ssh_without_shell_evaluation(self):
        source = Path(__file__).resolve().parents[3] / "vps/scripts/push.sh"
        with tempfile.TemporaryDirectory(prefix="tunnel-push-test-") as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "dist").mkdir()
            (root / "bin").mkdir()
            shutil.copyfile(source, root / "scripts/push.sh")
            (root / "VERSION").write_text("1.4.1\n")
            (root / "dist/umbrel-tunnel-1.4.1-linux-amd64.tar.gz").touch()
            (root / "bin/scp").write_text("#!/bin/sh\nexit 0\n")
            (root / "bin/scp").chmod(0o700)
            ssh = root / "bin/ssh"
            ssh.write_text(f"#!{sys.executable}\n" + '''
import base64, json, os, shlex, sys
if '-t' in sys.argv:
    command = shlex.split(sys.argv[-1])
    encoded = next(arg.split('=', 1)[1] for arg in command if arg.startswith('INSTALL_ARGS_B64='))
    args = base64.b64decode(encoded).decode().split('\\0')[:-1]
    with open(os.environ['CAPTURE'], 'w') as output:
        json.dump(args, output)
    script = sys.stdin.read()
    assert '"${install_args[@]}"' in script
''')
            ssh.chmod(0o700)
            capture = root / "args.json"
            env = {**os.environ, "PATH": str(root / "bin") + ":" + os.environ["PATH"], "CAPTURE": str(capture)}
            token = "token with spaces; $(touch " + str(root / "injected") + ")"
            base = ["bash", str(root / "scripts/push.sh"), "root@not-a-real-vps", "--arch", "amd64", "--no-build"]
            subprocess.run(base + ["--endpoint", "203.0.113.10", "--token", token, "--umbrel-pubkey", "public-key"], env=env, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(capture.read_text()), ["--endpoint", "203.0.113.10", "--token", token, "--umbrel-pubkey", "public-key"])
            self.assertFalse((root / "injected").exists())
            subprocess.run(base + ["--purge"], env=env, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(capture.read_text()), ["--uninstall", "--purge"])
