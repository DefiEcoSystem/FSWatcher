"""
Watcher is a daemon that monitors directories for file changes and runs jobs
"""
#!/usr/bin/env python
# Copyright (c) 2010 Greggory Hernandez

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

### BEGIN INIT INFO
# Provides:          watcher.py
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Monitor directories for file changes
# Description:       Monitor directories specified in /etc/watcher.ini for
#                    changes using the Kernel's inotify mechanism and run
#                    jobs when files or directories change
### END INIT INFO

import sys
import os
import time
import atexit
import argparse
from signal import SIGTERM
import datetime
from string import Template
import configparser
import pyinotify

class Daemon:
    """A generic daemon class"""

    # Usage: subclass the Daemon class and override the run method
    def __init__(
        self, pidfile, stdin="/dev/null", stdout="/dev/null", stderr="/dev/null"
    ):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        """
        Do the UNIX double-fork magic, see Stevens' "Advanced Programming in the
        UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as os_err:
            sys.stderr.write(f"fork #1 failed: {os_err.errno} ({os_err.strerror})\n")
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as os_err:
            sys.stderr.write(f"fork #2 failed: {os_err.errno} ({os_err.strerror})\n")
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        std_in = open(self.stdin, "r", encoding="utf-8")
        std_out = open(self.stdout, "a+", encoding="utf-8")
        std_err = open(self.stderr, "a+", encoding="utf-8")
        os.dup2(std_in.fileno(), sys.stdin.fileno())
        os.dup2(std_out.fileno(), sys.stdout.fileno())
        os.dup2(std_err.fileno(), sys.stderr.fileno())

        # write pid file
        atexit.register(self.delpid)
        pid = str(os.getpid())
        open(self.pidfile, "w+", encoding="utf-8").write(f"{pid}\n")

    def delpid(self):
        """
        Delete the pid file
        """
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pid_file = open(self.pidfile, "r", encoding="utf-8")
            pid = int(pid_file.read().strip())
            pid_file.close()
        except IOError:
            pid = None

        if pid:
            message = "pidfile %s already exists. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        # Start the Daemon
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # get the pid from the pidfile
        try:
            pid_file = open(self.pidfile, "r", encoding="utf-8")
            pid = int(pid_file.read().strip())
            pid_file.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            sys.stderr.write(message % self.pidfile)
            return  # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print(str(err))
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def status(self):
        """
        Check the status of the daemon
        """
        try:
            pid_file = open(self.pidfile, "r", encoding="utf-8")
            pid = int(pid_file.read().strip())
            pid_file.close()
        except IOError:
            pid = None

        if pid:
            print("service running")
            sys.exit(0)
        if not pid:
            print("service not running")
            sys.exit(3)

    def run(self):
        """
        This method will override when you subclass Daemon.
        It will be called after the process has been daemonized by start() or restart().
        """


class EventHandler(pyinotify.ProcessEvent):
    """
    This class is used to handle events from the inotify kernel subsystem.
    It is used by the WatchManager class.
    """

    def __init__(self, command):
        pyinotify.ProcessEvent.__init__(self)
        self.command = command

    def shellquote(self, string):
        """
        Prepares a string for use as a shell command.
        """
        # from http://stackoverflow.com/questions/35817/how-to-escape-os-system-calls-in-python
        string = str(string)
        return "'" + string.replace("'", "'\\''") + "'"

    def run_command(self, event):
        """
        Runs the command specified in the constructor.
        """
        template = Template(self.command)
        command = template.substitute(
            watched=self.shellquote(event.path),
            filename=self.shellquote(event.pathname),
            tflags=self.shellquote(event.maskname),
            nflags=self.shellquote(event.mask),
            cookie=self.shellquote(event.cookie if hasattr(event, "cookie") else 0),
        )
        try:
            os.system(command)
        except OSError as err:
            print(f"Failed to run command '{command}' {err}")

    def process_in_access(self, event):
        """
        This method is called on an access event.
        """
        print("Access: ", event.pathname)
        self.run_command(event)

    def process_in_attrib(self, event):
        """
        This method is called on an attrib event.
        """
        print("Attrib: ", event.pathname)
        self.run_command(event)

    def process_in_close_write(self, event):
        """
        This method is called on a close write event.
        """
        print("Close write: ", event.pathname)
        self.run_command(event)

    def process_in_close_nowrite(self, event):
        """
        This method is called on a close nowrite event.
        """
        print("Close nowrite: ", event.pathname)
        self.run_command(event)

    def process_in_create(self, event):
        """ "
        This method is called on a create event.
        """
        print("Creating: ", event.pathname)
        self.run_command(event)

    def process_in_delete(self, event):
        """
        This method is called on a delete event.
        """
        print("Deleteing: ", event.pathname)
        self.run_command(event)

    def process_in_modify(self, event):
        """
        This method is called on a modify event.
        """
        print("Modify: ", event.pathname)
        self.run_command(event)

    def process_in_move_self(self, event):
        """
        This method is called on a move self event.
        """
        print("Move self: ", event.pathname)
        self.run_command(event)

    def process_in_moved_from(self, event):
        """
        This method is called on a moved from event.
        """
        print("Moved from: ", event.pathname)
        self.run_command(event)

    def process_in_moved_to(self, event):
        """
        This method is called on a moved to event.
        """
        print("Moved to: ", event.pathname)
        self.run_command(event)

    def process_in_open(self, event):
        """
        This method is called on an open event.
        """
        print("Opened: ", event.pathname)
        self.run_command(event)


class WatcherDaemon(Daemon):
    """
    This class is used to daemonize the watcher.
    """
    # pylint: disable=redefined-outer-name, super-init-not-called
    def __init__(self, config):
        self.stdin = "/dev/null"
        self.stdout = config.get("DEFAULT", "logfile")
        self.stderr = config.get("DEFAULT", "logfile")
        self.pidfile = config.get("DEFAULT", "pidfile")
        self.config = config

    def run(self):
        log("Daemon started")
        wdds = []
        notifiers = []

        # read jobs from config file
        for section in self.config.sections():
            log(section + ": " + self.config.get(section, "watch"))
            # get the basic config info
            mask = self._parse_mask(self.config.get(section, "events").split(","))
            folder = self.config.get(section, "watch")
            recursive = self.config.getboolean(section, "recursive")
            autoadd = self.config.getboolean(section, "autoadd")
            excluded = self.config.get(section, "excluded")
            command = self.config.get(section, "command")

            # Exclude directories right away if 'excluded' regexp is set
            # Example https://github.com/seb-m/pyinotify/blob/master/python2/examples/exclude.py
            if excluded.strip() == "":  # if 'excluded' is empty or whitespaces only
                excl = None
            else:
                excl = pyinotify.ExcludeFilter(excluded.split(","))

            watch_manager = pyinotify.WatchManager()
            handler = EventHandler(command)

            wdds.append(
                watch_manager.add_watch(
                    folder, mask, rec=recursive, auto_add=autoadd, exclude_filter=excl
                )
            )

            # BUT we need a new ThreadNotifier so I can specify a different
            # EventHandler instance for each job
            # this means that each job has its own thread as well (I think)
            notifiers.append(pyinotify.ThreadedNotifier(watch_manager, handler))

        # now we need to start ALL the notifiers.
        for notifier in notifiers:
            notifier.start()

    def _parse_mask(self, masks):
        ret = False

        for mask in masks:
            mask = mask.strip()

            if "access" == mask:
                ret = self._add_mask(pyinotify.IN_ACCESS, ret)
            elif "attribute_change" == mask:
                ret = self._add_mask(pyinotify.IN_ATTRIB, ret)
            elif "write_close" == mask:
                ret = self._add_mask(pyinotify.IN_CLOSE_WRITE, ret)
            elif "nowrite_close" == mask:
                ret = self._add_mask(pyinotify.IN_CLOSE_NOWRITE, ret)
            elif "create" == mask:
                ret = self._add_mask(pyinotify.IN_CREATE, ret)
            elif "delete" == mask:
                ret = self._add_mask(pyinotify.IN_DELETE, ret)
            elif "self_delete" == mask:
                ret = self._add_mask(pyinotify.IN_DELETE_SELF, ret)
            elif "modify" == mask:
                ret = self._add_mask(pyinotify.IN_MODIFY, ret)
            elif "self_move" == mask:
                ret = self._add_mask(pyinotify.IN_MOVE_SELF, ret)
            elif "move_from" == mask:
                ret = self._add_mask(pyinotify.IN_MOVED_FROM, ret)
            elif "move_to" == mask:
                ret = self._add_mask(pyinotify.IN_MOVED_TO, ret)
            elif "open" == mask:
                ret = self._add_mask(pyinotify.IN_OPEN, ret)
            elif "all" == mask:
                all_mask = (
                    pyinotify.IN_ACCESS
                    | pyinotify.IN_ATTRIB
                    | pyinotify.IN_CLOSE_WRITE
                    | pyinotify.IN_CLOSE_NOWRITE
                    | pyinotify.IN_CREATE
                    | pyinotify.IN_DELETE
                    | pyinotify.IN_DELETE_SELF
                    | pyinotify.IN_MODIFY
                    | pyinotify.IN_MOVE_SELF
                    | pyinotify.IN_MOVED_FROM
                    | pyinotify.IN_MOVED_TO
                    | pyinotify.IN_OPEN
                )
                ret = self._add_mask(all_mask, ret)
            elif "move" == mask:
                ret = self._add_mask(
                    pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO, ret
                )
            elif "close" == mask:
                ret = self._add_mask(
                    pyinotify.IN_CLOSE_WRITE | pyinotify.IN_CLOSE_NOWRITE, ret
                )

        return ret

    def _add_mask(self, new_option, current_options):
        if not current_options:
            return new_option
        else:
            return current_options | new_option


def log(msg):
    """
    Log a message to stdout
    """
    sys.stdout.write(f"{datetime.datetime.now()} {msg}\n")



if __name__ == "__main__":
    # Parse commandline arguments
    parser = argparse.ArgumentParser(
        description="Monitor changes within specified dirs and run commands on these changes.",
    )
    parser.add_argument(
        "-c",
        "--config",
        action="store",
        help="Path to the config file (default: %(default)s)",
    )
    parser.add_argument(
        "command",
        action="store",
        choices=["start", "stop", "restart", "status", "debug"],
        help="What to do. Use debug to start in the foreground",
    )
    args = parser.parse_args()

    # Parse the config file
    config = configparser.ConfigParser()
    if args.config:
        confok = config.read(args.config)
    else:
        confok = config.read(["/etc/watcher.ini", os.path.expanduser("~/.watcher.ini")])

    if not confok:
        sys.stderr.write("Failed to read config file. Try -c parameter\n")
        sys.exit(4)

    # Initialize the daemon
    daemon = WatcherDaemon(config)

    # Execute the command
    if "start" == args.command:
        daemon.start()
    elif "stop" == args.command:
        daemon.stop()
    elif "restart" == args.command:
        daemon.restart()
    elif "status" == args.command:
        daemon.status()
    elif "debug" == args.command:
        daemon.run()
    else:
        print("Unkown Command")
        sys.exit(2)
    sys.exit(0)
