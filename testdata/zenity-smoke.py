#!/usr/bin/env python3
"""Isolated Linux/X11 smoke test: Xvfb, zenity, libX11 and libXtst required.

Usage: python3 testdata/zenity-smoke.py /absolute/path/sshx-prompt-zenity
Only synthetic passphrases are used. No active desktop display is accessed.
"""
import base64
import ctypes as C
import ctypes.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def main():
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="sshx-zenity-smoke-") as directory:
        display_file = Path(directory) / "display"
        with display_file.open("w+") as fd:
            server = subprocess.Popen(["Xvfb", "-displayfd", str(fd.fileno()),
                                       "-screen", "0", "1024x1024x24", "-nolisten", "tcp"],
                                      pass_fds=(fd.fileno(),), stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                number = display_file.read_text().strip()
                if number:
                    break
                time.sleep(.05)
            else:
                raise RuntimeError("Xvfb failed to start")
            display_name = ":" + number
            env = dict(os.environ, DISPLAY=display_name, GDK_BACKEND="x11")
            # GTK can discover wayland-0 from XDG_RUNTIME_DIR even without
            # WAYLAND_DISPLAY. Isolate runtime and bus too: the helper deliberately
            # does not inherit GDK_BACKEND or other arbitrary environment options.
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + str(runtime / "no-bus")
            env.pop("WAYLAND_DISPLAY", None)
            x = C.CDLL(ctypes.util.find_library("X11"))
            xt = C.CDLL(ctypes.util.find_library("Xtst"))
            x.XOpenDisplay.argtypes = [C.c_char_p]
            x.XOpenDisplay.restype = C.c_void_p
            display = x.XOpenDisplay(display_name.encode())
            assert display, "cannot connect to isolated display"
            x.XDefaultRootWindow.argtypes = [C.c_void_p]
            x.XDefaultRootWindow.restype = C.c_ulong
            root = x.XDefaultRootWindow(display)
            x.XQueryTree.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(C.c_ulong),
                                    C.POINTER(C.c_ulong), C.POINTER(C.POINTER(C.c_ulong)),
                                    C.POINTER(C.c_uint)]
            x.XFetchName.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(C.c_void_p)]
            x.XFree.argtypes = [C.c_void_p]
            x.XInternAtom.argtypes = [C.c_void_p, C.c_char_p, C.c_int]
            x.XInternAtom.restype = C.c_ulong
            name_atom = x.XInternAtom(display, b"_NET_WM_NAME", 0)
            x.XGetWindowProperty.argtypes = [C.c_void_p, C.c_ulong, C.c_ulong,
                                            C.c_long, C.c_long, C.c_int, C.c_ulong,
                                            C.POINTER(C.c_ulong), C.POINTER(C.c_int),
                                            C.POINTER(C.c_ulong), C.POINTER(C.c_ulong),
                                            C.POINTER(C.c_void_p)]
            x.XStringToKeysym.argtypes = [C.c_char_p]
            x.XStringToKeysym.restype = C.c_ulong
            x.XKeysymToKeycode.argtypes = [C.c_void_p, C.c_ulong]
            x.XKeysymToKeycode.restype = C.c_uint
            xt.XTestFakeKeyEvent.argtypes = [C.c_void_p, C.c_uint, C.c_int, C.c_ulong]
            x.XFlush.argtypes = [C.c_void_p]
            x.XSetInputFocus.argtypes = [C.c_void_p, C.c_ulong, C.c_int, C.c_ulong]
            x.XCloseDisplay.argtypes = [C.c_void_p]
            class Attributes(C.Structure):
                _fields_ = [(name, kind) for name, kind in (
                    ("x", C.c_int), ("y", C.c_int), ("width", C.c_int), ("height", C.c_int),
                    ("border", C.c_int), ("depth", C.c_int), ("visual", C.c_void_p),
                    ("root", C.c_ulong), ("class_", C.c_int), ("bit_gravity", C.c_int),
                    ("win_gravity", C.c_int), ("backing_store", C.c_int),
                    ("backing_planes", C.c_ulong), ("backing_pixel", C.c_ulong),
                    ("save_under", C.c_int), ("colormap", C.c_ulong),
                    ("map_installed", C.c_int), ("map_state", C.c_int),
                    ("all_events", C.c_long), ("events", C.c_long), ("dont_propagate", C.c_long),
                    ("override_redirect", C.c_int), ("screen", C.c_void_p))]
            x.XGetWindowAttributes.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(Attributes)]

            def windows():
                parent, root_return = C.c_ulong(), C.c_ulong()
                children, count = C.POINTER(C.c_ulong)(), C.c_uint()
                x.XQueryTree(display, root, C.byref(root_return), C.byref(parent),
                             C.byref(children), C.byref(count))
                result = []
                for i in range(count.value):
                    name = C.c_void_p()
                    kind, remaining, size = C.c_ulong(), C.c_ulong(), C.c_ulong()
                    fmt = C.c_int()
                    x.XGetWindowProperty(display, children[i], name_atom, 0, 1024, 0, 0,
                                         C.byref(kind), C.byref(fmt), C.byref(size),
                                         C.byref(remaining), C.byref(name))
                    if name.value:
                        title = C.string_at(name).decode(errors="replace")
                        attributes = Attributes()
                        mapped = x.XGetWindowAttributes(display, children[i], C.byref(attributes))
                        if title.startswith("sshx local") and mapped and attributes.map_state == 2:
                            result.append(children[i])
                        x.XFree(name)
                if children:
                    x.XFree(children)
                return result

            def key(name):
                code = x.XKeysymToKeycode(display, x.XStringToKeysym(name.encode()))
                assert code, name
                xt.XTestFakeKeyEvent(display, code, 1, 0)
                xt.XTestFakeKeyEvent(display, code, 0, 0)
                x.XFlush(display)
                time.sleep(.02)

            def launch(operation):
                request = dict(version=1, request_id="a" * 64, operation=operation,
                               key_fingerprint="SHA256:" + base64.b64encode(bytes(32)).decode().rstrip("="),
                               data_digest="b" * 64, algorithm="ssh-ed25519",
                               destination={"status": "unknown"})
                if operation == "select-credential":
                    # Deliberately identical metadata: only ordinal rows/tokens
                    # distinguish the choices, never a lookup by label/target.
                    request = dict(version=2, request_id="a" * 64, operation=operation,
                                   options=[dict(token=token * 64, display=dict(
                                       label="same label", target="alice@host",
                                       backend="gopass", collection="")) for token in ("b", "c")])
                process = subprocess.Popen([executable], env=env, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                process.stdin.write(json.dumps(request).encode())
                process.stdin.close()
                process.stdin = None
                for _ in range(400):
                    visible = windows()
                    if visible:
                        x.XSetInputFocus(display, visible[0], 1, 0)
                        x.XFlush(display)
                        time.sleep(.2)
                        return process
                    if process.poll() is not None:
                        raise RuntimeError("helper exited before showing dialog")
                    time.sleep(.05)
                process.kill()
                process.wait()
                raise RuntimeError("dialog did not appear")

            def finish(process, version=1):
                out, err = process.communicate(timeout=5)
                assert process.returncode == 0 and not err, (process.returncode, err)
                response = json.loads(out)
                assert response["request_id"] == "a" * 64 and response["version"] == version
                return response

            def wait_closed():
                # Process exit and the X server's DestroyNotify are asynchronous.
                for _ in range(100):
                    if not windows():
                        return
                    time.sleep(.05)
                raise AssertionError("dialog survived helper cleanup")

            process = launch("confirm")
            key("Return")
            assert finish(process)["approved"] is False, "Enter did not default to Reject"
            print("PASS: confirmation defaults to Reject")

            process = launch("confirm")
            key("Tab")
            key("Return")
            assert finish(process)["approved"] is True
            print("PASS: explicit Allow once")

            process = launch("passphrase")
            for character in "smokesecret":
                key(character)
            # Optional artifact for visual inspection of masking, never a real secret.
            if os.environ.get("SSHX_ZENITY_SMOKE_SCREENSHOT"):
                subprocess.run(["import", "-display", display_name, "-window", "root",
                                os.environ["SSHX_ZENITY_SMOKE_SCREENSHOT"]], check=True)
            key("Return")
            response = finish(process)
            assert response["approved"] and base64.b64decode(response["passphrase"]) == b"smokesecret"
            print("PASS: passphrase entry and base64 response")

            process = launch("passphrase")
            key("Return")
            assert finish(process)["approved"] is False
            print("PASS: empty passphrase denies")

            process = launch("select-credential")
            key("Escape")
            response = finish(process, version=2)
            assert response["approved"] is False and "token" not in response
            wait_closed()
            print("PASS: selection cancellation has no token")

            process = launch("select-credential")
            key("Home")
            key("Down")
            key("Return")
            response = finish(process, version=2)
            assert response["approved"] and response["token"] == "c" * 64
            wait_closed()
            print("PASS: duplicate labels return the second original token")

            for sig in (signal.SIGTERM, signal.SIGKILL):
                process = launch("select-credential")
                process.send_signal(sig)
                out, _ = process.communicate(timeout=5)
                assert not out and process.returncode != 0
                wait_closed()
                print("PASS: dialog cleanup after", sig.name)

            process = launch("passphrase")
            out, err = process.communicate(timeout=35)
            assert not out and process.returncode != 0 and err == b"desktop prompt failed\n"
            wait_closed()
            print("PASS: local 30-second deadline removes dialog")
            x.XCloseDisplay(display)
        finally:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
