#!/usr/bin/env python3

import datetime
import logging
import os
import re
import signal
import sys
import time

import vrnetlab

STARTUP_CONFIG_FILE = "/config/startup-config.cfg"


def handle_SIGCHLD(signal, frame):
    os.waitpid(-1, os.WNOHANG)


def handle_SIGTERM(signal, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)


logging.Logger.trace = trace


class PICOS_vm(vrnetlab.VM):
    def __init__(self, hostname, username, password, conn_mode):
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e
        super(PICOS_vm, self).__init__(
            username, password, disk_image=disk_image, ram=2048
        )
        self.hostname = hostname
        self.conn_mode = conn_mode
        self.num_nics = 128
        self.nic_type = "virtio-net-pci"
        self.qemu_args.extend(["-cpu", "host", "-smp", "2,sockets=1,cores=1"])

    def bootstrap_spin(self):
        """This function should be called periodically to do work."""

        if self.spins > 300:
            # too many spins with no result ->  give up
            self.stop()
            self.start()
            return

        (ridx, match, res) = self.tn.expect([b"login:"], 1)
        if match:  # got a match!
            if ridx == 0:  # login
                self.logger.trace("OUTPUT: %s" % res.decode())
                self.logger.debug("matched login prompt")
                if (self.bootstrap_login() == 0):
                    # run main config!
                    self.bootstrap_config()
                    self.startup_config()
                    # close telnet connection
                    self.tn.close()
                    # startup time?
                    startup_time = datetime.datetime.now() - self.start_time
                    self.logger.info("Startup complete in: %s" % startup_time)
                    # mark as running
                    self.running = True
                    return
        else:
            # no match, if we saw some output from the VM it's probably
            # booting, so let's give it some more time
            if res != b"":
                self.logger.trace("OUTPUT: %s" % res.decode())
                # reset spins if we saw some output
                self.spins = 0

        self.spins += 1

        return

    def bootstrap_login(self):
        """Login PICOS"""
        self.logger.debug("trying to log in with admin / pica8")
        self.wait_write("admin", wait=None)
        self.wait_write("pica8", wait="Password:")
        flag = False
        while True:
            (ridx, match, res) = self.tn.expect(
                [b"login:", b"Current password:", re.compile(b".*@.*>")]
            )
            if match: # got a match!
                self.logger.trace("OUTPUT: %s" % res.decode())
                if ridx == 0:  # login incorrect
                    if flag:
                        return 1
                    flag = True
                    self.logger.debug(
                        "trying to log in with %s / %s" % (self.username, self.password)
                    )
                    self.wait_write(self.username, wait=None)
                    self.wait_write(self.password, wait="Password:")
                    continue
                elif ridx == 1: # changing admin password
                    self.logger.debug(
                        "changing admin password to %s" % self.password
                    )
                    self.wait_write("pica8", wait=None)
                    self.wait_write(self.password, wait="New password:")
                    self.wait_write(self.password, wait="Retype new password:")
                    continue
                elif ridx == 2: # login correct
                    self.logger.debug("log in PICOS")
                    return 0
            return -1

    def bootstrap_config(self):
        """Do the actual bootstrap config"""
        self.logger.info("applying bootstrap configuration")
        self.wait_write("", wait=None)
        self.wait_write("configure", '>')
        self.wait_write_cfg("set system login user %s class super-user" % self.username)
        self.wait_write_cfg(
            "set system login user %s authentication plain-text-password %s"
            % (self.username, self.password)
        )
        self.wait_write_cfg("set system hostname %s" % (self.hostname))

        # configure mgmt interface
        self.wait_write_cfg("set system management-ethernet eth0 ip-address IPv4 10.0.0.15/24")
        self.wait_write_cfg("commit")
        self.wait_write_cfg("exit")

    def startup_config(self):
        """Load additional config provided by user."""

        if not os.path.exists(STARTUP_CONFIG_FILE):
            self.logger.trace(f"Startup config file {STARTUP_CONFIG_FILE} is not found")
            return

        self.logger.trace(f"Startup config file {STARTUP_CONFIG_FILE} exists")
        with open(STARTUP_CONFIG_FILE) as file:
            config_lines = file.readlines()
            config_lines = [line.rstrip() for line in config_lines]
            self.logger.trace(f"Parsed startup config file {STARTUP_CONFIG_FILE}")

        self.logger.info(f"Writing lines from {STARTUP_CONFIG_FILE}")

        self.wait_write("", wait=None)
        self.wait_write("configure", '>')
        # Apply lines from file
        for line in config_lines:
            self.wait_write_cfg(line)
        # End and Save
        self.wait_write_cfg("commit")
        self.wait_write_cfg("exit")
        self.logger.info("Done loading config file %s" % STARTUP_CONFIG_FILE)

    def wait_write_cfg(self, cmd, timeout=None):
        """Wait for '.*@.*# $' and then send command"""
        (ridx, match, res) = self.tn.expect(
            [re.compile(b".*@.*# $")], timeout=timeout
        )
        self.logger.trace("OUTPUT:\n%s" % res.decode())
        res = self.tn.read_very_eager()
        if res != b"":
            self.logger.trace("OUTPUT:\n%s" % res.decode())

        self.logger.debug("writing to serial console: '%s'" % cmd)
        self.tn.write("{}\n".format(cmd).encode())


class PICOS(vrnetlab.VR):
    def __init__(self, hostname, username, password, conn_mode):
        super(PICOS, self).__init__(username, password)
        self.vms = [PICOS_vm(hostname, username, password, conn_mode)]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--trace", action="store_true", help="enable trace level logging"
    )
    parser.add_argument("--hostname", default="vr-picos", help="PICOS hostname")
    parser.add_argument("--username", default="vrnetlab", help="Username")
    parser.add_argument("--password", default="VR-netlab9", help="Password")
    parser.add_argument(
        "--connection-mode",
        default="tc",
        help="Connection mode to use in the datapath",
    )
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    vrnetlab.boot_delay()
    vr = PICOS(
        args.hostname, args.username, args.password, conn_mode=args.connection_mode
    )
    vr.start()
