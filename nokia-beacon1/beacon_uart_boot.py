#!/usr/bin/env python3
"""Boot a Nokia Wi-Fi Beacon 1 (HA-020W-B) into a UART shell.

What it does
------------
1. Serves a modified device tree (default ``96846-init.dtb``) over TFTP from
   this machine, on the address the Beacon's CFE can reach (default
   192.168.1.100).
2. Starts picocom on the UART and holds the boot loader at its prompt by
   sending Ctrl-C several times a second, while asking you to power the board.
3. When ``CFE>`` appears it sends ``ldt <host>:<file>``, waits for
   ``command status = 0``, then sends ``r``. The board reboots, the flash
   kernel starts with the RAM-resident DTB, and init is ``/bin/sh`` on ttyS0.
   The console stays attached afterwards.

Nothing is written to flash: ``ldt`` copies the DTB into CFE RAM and ``r``
boots the stock flash kernel with it. A power cycle restores the vendor boot.

Typical run (on the Pi, where this lives in persistent storage):

    sudo ip addr add 192.168.1.100/24 dev eth1     # if not already there
    sudo /srv/beacon/beacon_uart_boot.py

    [tftp] serving /srv/beacon/dtb on 192.168.1.100:69
    [ser]  picocom -b 115200 /dev/ttyUSB0 (pid 4711)
    [ser]  sending Ctrl-C 5x/s -- TURN THE BEACON ON NOW
    [cfe]  prompt seen
    [cfe]  ldt 192.168.1.100:96846-init.dtb
    [cfe]  loaded, status 0 -- rebooting
    [sh]   /bin/sh is up (PID 1) -- type commands, Ctrl-C to quit

Test the TFTP half without a board:  --dry-run
"""

import argparse
import hashlib
import os
import pty
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

DEFAULT_DTB = "/srv/beacon/dtb/96846-init.dtb"
DEFAULT_HOST = "192.168.1.100"
DEFAULT_SERIAL = "/dev/ttyUSB0"
DEFAULT_BAUD = 115200


def say(msg):
    """Script status goes to stderr so stdout stays a clean console copy."""
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# TFTP (RFC 1350, read-only, 512-byte blocks)
# --------------------------------------------------------------------------

class TFTPServer(threading.Thread):
    OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR = 1, 2, 3, 4, 5

    def __init__(self, host, port, directory):
        super().__init__(daemon=True)
        self.host, self.port, self.dir = host, port, directory
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)

    def run(self):
        while not self.stop.is_set():
            try:
                packet, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(packet, addr)
            except Exception as exc:                      # never kill the server
                say("[tftp] %s: %s" % (addr[0], exc))

    def _handle(self, packet, addr):
        if len(packet) < 4:
            return
        opcode = struct.unpack("!H", packet[:2])[0]
        if opcode == self.OP_WRQ:
            self._error(addr, 2, "read-only server")
            say("[tftp] refusing write from %s" % addr[0])
            return
        if opcode != self.OP_RRQ:
            return

        fields = packet[2:].split(b"\x00")
        name = fields[0].decode("ascii", "replace")
        # The whole directory is served, but only flat names: no traversal.
        path = os.path.join(self.dir, os.path.basename(name))
        if not os.path.isfile(path):
            self._error(addr, 1, "file not found")
            say("[tftp] %s requested %r: not found" % (addr[0], name))
            return

        size = os.path.getsize(path)
        say("[tftp] %s reads %r (%d bytes)" % (addr[0], os.path.basename(path), size))

        # TFTP requires the transfer to come from a fresh port.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data_sock:
            data_sock.bind((self.host, 0))
            data_sock.settimeout(2.0)
            sent = self._send_file(data_sock, path, addr)
        if sent:
            say("[tftp] %d bytes acknowledged by %s" % (size, addr[0]))

    def _send_file(self, sock, path, addr):
        with open(path, "rb") as fh:
            block = 1
            while True:
                chunk = fh.read(512)
                packet = struct.pack("!HH", self.OP_DATA, block) + chunk
                for _ in range(5):
                    sock.sendto(packet, addr)
                    try:
                        reply, _src = sock.recvfrom(1024)
                    except socket.timeout:
                        continue
                    if (len(reply) >= 4
                            and struct.unpack("!HH", reply[:4]) == (self.OP_ACK, block)):
                        break
                else:
                    say("[tftp] no ACK for block %d, giving up" % block)
                    return False
                if len(chunk) < 512:          # last block (possibly empty)
                    return True
                block = (block + 1) & 0xFFFF

    def _error(self, addr, code, text):
        try:
            self.sock.sendto(struct.pack("!HH", self.OP_ERROR, code)
                             + text.encode() + b"\x00", addr)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Serial console: picocom on a pty, driven by this script
# --------------------------------------------------------------------------

class Console:
    """picocom on /dev/ttyUSB0, with its terminal on a pty we control.

    Writing to the pty master is the same as typing on picocom's keyboard, so
    Ctrl-C and the CFE commands reach the UART exactly as if they were typed.
    Everything picocom prints is captured, echoed to stdout and written to the
    transcript file.
    """

    def __init__(self, device, baud, transcript):
        self.master, slave = pty.openpty()
        try:
            self.proc = subprocess.Popen(
                ["picocom", "-b", str(baud), "-q", device],
                stdin=slave, stdout=slave, stderr=slave,
                start_new_session=True)
        finally:
            os.close(slave)
        os.set_blocking(self.master, False)
        self.transcript = open(transcript, "wb")
        self.text = ""
        self.raw = b""

    def write(self, data):
        try:
            os.write(self.master, data)
        except OSError:
            pass

    def alive(self):
        return self.proc.poll() is None

    def pump(self, timeout=0.1):
        """Copy whatever arrived; return the newly decoded text."""
        try:
            ready, _, _ = select.select([self.master], [], [], timeout)
        except InterruptedError:
            return ""
        if not ready:
            return ""
        try:
            chunk = os.read(self.master, 4096)
        except OSError:                       # EIO once picocom exits
            chunk = b""
        if not chunk:
            return ""
        self.raw += chunk
        self.transcript.write(chunk)
        self.transcript.flush()
        sys.stdout.write(chunk.decode("utf-8", "replace"))
        sys.stdout.flush()
        self.text = (self.text + chunk.decode("utf-8", "replace"))[-8000:]
        return chunk

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        try:
            os.close(self.master)
        except OSError:
            pass
        self.transcript.close()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def local_addresses():
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))


def file_digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_until(console, needle, timeout, tick=None, interval=0.2):
    """Pump the console until `needle` appears in the recent output."""
    end = time.time() + timeout
    while time.time() < end:
        if not console.alive():
            return False
        console.pump(interval)
        if needle in console.text:
            return True
        if tick:
            tick()
    return False


def forward_stdin(console):
    """After the shell is up, every line typed here goes down the UART."""
    try:
        for line in sys.stdin:
            console.write(line.rstrip("\n").encode() + b"\r")
    except (OSError, ValueError):
        pass


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Serve the DTB over TFTP, catch the CFE prompt, load the "
                    "DTB and reboot the Nokia Beacon into a UART shell.")
    ap.add_argument("--dtb", default=DEFAULT_DTB,
                    help="device tree to serve (default %(default)s); the "
                         "file's directory becomes the TFTP root")
    ap.add_argument("--bind", default=DEFAULT_HOST,
                    help="address to serve TFTP on, must match the CFE host IP "
                         "(default %(default)s)")
    ap.add_argument("--port", type=int, default=69, help="TFTP port (default 69)")
    ap.add_argument("--serial", default=DEFAULT_SERIAL,
                    help="UART device (default %(default)s)")
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD,
                    help="UART speed (default %(default)s)")
    ap.add_argument("--power-timeout", type=float, default=180,
                    help="seconds to wait for power-on + CFE prompt (default 180)")
    ap.add_argument("--load-timeout", type=float, default=20,
                    help="seconds to wait for 'command status = 0' (default 20)")
    ap.add_argument("--boot-timeout", type=float, default=240,
                    help="seconds to wait for /bin/sh after 'r' (default 240)")
    ap.add_argument("--transcript", default=None,
                    help="capture file (default beacon-uart-<time>.log)")
    ap.add_argument("--dry-run", action="store_true",
                    help="serve TFTP only; do not touch the serial port")
    args = ap.parse_args(argv)

    dtb = os.path.abspath(args.dtb)
    if not os.path.isfile(dtb):
        say("[abort] %s does not exist" % dtb)
        say("        copy the modified DTB there first, e.g.")
        say("        scp work/out/fw/96846-init.dtb pi:/tmp/ && "
            "sudo install -m 644 /tmp/96846-init.dtb /srv/beacon/dtb/")
        return 2
    tftp_dir, tftp_name = os.path.dirname(dtb), os.path.basename(dtb)

    if args.bind not in local_addresses():
        say("[abort] %s is not an address on this machine" % args.bind)
        say("        add it on the interface facing the Beacon, e.g.")
        say("        sudo ip addr add %s/24 dev eth1" % args.bind)
        say("        (the CFE host IP must match: it is the address CFE fetches from)")
        return 2

    say("[tftp] serving %s on %s:%d" % (tftp_dir, args.bind, args.port))
    say("[tftp] %s: %d bytes, sha256 %s"
        % (tftp_name, os.path.getsize(dtb), file_digest(dtb)[:16] + "..."))
    try:
        server = TFTPServer(args.bind, args.port, tftp_dir)
    except PermissionError:
        say("[abort] binding port %d needs root (or CAP_NET_BIND_SERVICE); "
            "run with sudo, or use --port above 1024 and set it in CFE"
            % args.port)
        return 2
    except OSError as exc:
        say("[abort] cannot bind %s:%d: %s" % (args.bind, args.port, exc))
        return 2
    server.start()

    if args.dry_run:
        say("[dry-run] TFTP is up; Ctrl-C to stop")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            server.stop.set()
        return 0

    stamp = time.strftime("%Y%m%d-%H%M%S")
    transcript = args.transcript or "beacon-uart-%s.log" % stamp
    try:
        console = Console(args.serial, args.baud, transcript)
    except (OSError, subprocess.SubprocessError) as exc:
        say("[abort] cannot start picocom on %s: %s" % (args.serial, exc))
        server.stop.set()
        return 2
    time.sleep(0.5)
    if not console.alive():
        console.pump(0.2)                    # show picocom's own complaint
        say("[abort] picocom exited at once -- is %s busy or missing?"
            % args.serial)
        say("        stop any other picocom/minicom holding it and retry")
        console.close()
        server.stop.set()
        return 2

    say("[ser]  picocom -b %d %s (pid %d)" % (args.baud, args.serial, console.proc.pid))
    say("[ser]  transcript: %s" % transcript)
    say("[ser]  sending Ctrl-C 5x/s -- TURN THE BEACON ON NOW")

    rc = 0
    try:
        # --- 1. hold the boot loader, wait for its prompt -------------------
        last_ctrl_c = 0.0

        def hammer():
            nonlocal last_ctrl_c
            if time.time() - last_ctrl_c >= 0.2:
                console.write(b"\x03")
                last_ctrl_c = time.time()

        if not wait_until(console, "CFE>", args.power_timeout, tick=hammer):
            if not console.alive():
                say("[abort] picocom exited during power-on (transcript kept)")
            else:
                say("[abort] no CFE prompt within %.0fs -- check the cable, the "
                    "power, and that the Beacon's UART is 115200 8N1"
                    % args.power_timeout)
            return 1

        say("[cfe]  prompt seen")
        time.sleep(0.3)                      # let the prompt settle
        # A Ctrl-C or two may have landed after the prompt appeared. CFE's line
        # editor handles backspace for certain, so rub out anything typed.
        console.write(b"\x08" * 16)

        # --- 2. load the DTB over TFTP --------------------------------------
        command = "ldt %s:%s" % (args.bind, tftp_name)
        say("[cfe]  %s" % command)
        console.write(command.encode() + b"\r")

        if not wait_until(console, "command status", args.load_timeout):
            say("[abort] no 'command status' from CFE -- see the transcript")
            return 1
        m = re.search(r"command status\s*=\s*(-?\d+)", console.text)
        if not m:
            say("[abort] could not read the command status -- see the transcript")
            return 1
        status = int(m.group(1))
        if status != 0:
            say("[abort] CFE reported status %d (TFTP or file problem)" % status)
            return 1
        say("[cfe]  loaded, status 0")

        # --- 3. reboot into the RAM-resident DTB ----------------------------
        time.sleep(0.3)
        say("[cfe]  r -- rebooting into the DTB")
        console.text = ""
        console.write(b"r\r")

        if not wait_until(console, "/ #", args.boot_timeout):
            say("[warn] no '/ #' prompt within %.0fs; the boot output is above "
                "and in %s" % (args.boot_timeout, transcript))
            rc = 1
        else:
            say("[sh]   /bin/sh is up (PID 1) -- type commands, Ctrl-C to quit")

        # --- 4. hand the console over ---------------------------------------
        threading.Thread(target=forward_stdin, args=(console,), daemon=True).start()
        while console.alive():
            console.pump(0.2)
        return rc
    except KeyboardInterrupt:
        say("[exit] interrupted")
        return 130
    finally:
        console.close()
        server.stop.set()
        say("[exit] transcript: %s" % transcript)


if __name__ == "__main__":
    sys.exit(main())
