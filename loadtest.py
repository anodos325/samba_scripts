from samba.samba3 import libsmb_samba_internal as libsmb
from samba.dcerpc import security
from samba.samba3 import param as s3param
from samba import credentials
from samba import NTSTATUSError
import argparse
import getpass
import threading
import sys
import os
import time


class Open_Close(threading.Thread):
    def __init__(self, conn, filename, num_ops):
        threading.Thread.__init__(self)
        self.conn = conn
        self.filename = filename
        self.num_ops = num_ops
        self.exc = False
        self.finished = threading.Event()

    def run(self):
        c = self.conn
        if args.share_type == 'BASIC':
            for file in ['Desktop.ini', 'AutoRun.inf']:
                self.finished.wait(args.waittime)
                try:
                    """
                    CreateDisposition=1 File exists open. File not exist fail.
                    """
                    f = c.create(
                        file,
                        CreateDisposition=1,
                        DesiredAccess=security.SEC_GENERIC_READ,
                    )
                    c.close(f)
                except NTSTATUSError as e:
                    if e.args[1] == 'The object name is not found.':
                        pass
                    else:
                        self.exc = sys.exc_info()

                except Exception:
                    self.exc = sys.exc_info()

        elif args.share_type == 'TEST_OPS':
            for i in range(self.num_ops):
                try:
                    testfiles={}
                    c.mkdir(self.filename)
                    c.list(self.filename)
                    for b in range(6):
                        self.finished.wait(args.waittime)
                        testfiles[b] = c.create(
                            f"{self.filename}/file_{b}",
                            CreateDisposition=3,
                            DesiredAccess=security.SEC_GENERIC_ALL,
                        )
                    for b in range(6):
                        self.finished.wait(args.waittime)
                        c.write(testfiles[b], os.urandom(1024), 0)

                    for b in range(6):
                        self.finished.wait(args.waittime)
                        c.read(testfiles[b], 0, 1024)

                    for b in range(6):
                        self.finished.wait(args.waittime)
                        c.delete_on_close(testfiles[b], True)
                        c.close(testfiles[b])

                    c.rmdir(self.filename)
 
                except Exception:
                    print("preparing to exit")
                    self.exc = sys.exc_info()

        else:
            for i in range(self.num_ops):
                try:
                    f = c.create(
                        self.filename,
                        CreateDisposition=3,
                        DesiredAccess=security.SEC_GENERIC_ALL,
                        ShareAccess=2
                    )
                    c.delete_on_close(f, True)
                    c.close(f)
                except Exception:
                    self.exc = sys.exc_info()


def GenerateSessions():
    lp = s3param.get_context()
    lp.load('/usr/local/etc/smb4.conf')
    creds = credentials.Credentials()
    creds.guess(lp)
    if args.domain is not None:
        creds.set_domain(args.domain)

    creds.set_password(args.password)

    mythreads = []
    c = {}
    for i in range(args.count):
        if args.increment is None:
            creds.set_username(args.user)
        else:
            creds.set_username(f'{args.user}{args.increment}')

        c[i] = libsmb.Conn(args.host, args.share, lp, creds)
        t = Open_Close(c[i], "test" + str(i), args.numops)
        mythreads.append(t)

    for t in mythreads:
        t.start()


    for t in mythreads:
        t.join()
        if t.exc:
            raise t.exc[0](t.exc[1])


    time.sleep(60)

def parse_args():
    
    global args

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-d', '--domain',
        help='Active Directory Domain (default None)',
        default=None)
    parser.add_argument(
        '-t', '--share_type',
        help='Specify type of share to emulate.',
        default='BASIC') 
    parser.add_argument(
        '-U', '--user',
        help="username",
        default=None)
    parser.add_argument(
        '-P', '--password',
        help='password to use',
        default=None)
    parser.add_argument(
        '-n', '--numops',
        help='number of times each thread should perform the ops',
        type=int, default=1)
    parser.add_argument(
        '-c', '--count',
        help='session count', type=int,
        default=500)
    parser.add_argument(
        '-w', '--waittime',
        help='wait between operations', type=int,
        default=1)
    parser.add_argument(
        '-H', '--host',
        help='hostname or ip address of server',
        default=None)
    parser.add_argument(
        '-i', '--increment',
        help='automatically increment username (bob1, bob2, etc) with specified number as base.',
        type=int, default=None)
    parser.add_argument(
        '-s', '--share',
        help='share name',
        default=None)

    args = parser.parse_args(sys.argv[1:])


def main():
    parse_args()
    if args.user is None:
       args.user = getpass.getuser()

    if args.password is None:
       args.password = getpass.getpass(prompt=f"Password for [{args.user}]:")
    print(args)
    GenerateSessions()

if __name__ == '__main__':
    sys.exit(main())
