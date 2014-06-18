
import copy
import logging
import os.path
import select
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time

import paramiko.rsakey
import paramiko.server
import paramiko.sftp_attr
import paramiko.sftp_si
import paramiko.transport

import org.wayround.utils.path
import org.wayround.utils.stream
import org.wayround.xmpp.core


# directories structures:
#
# working_root_dir--+
#                   |
#                   +--user_0
#                   +--user_1
#                   +--...
#                   +--user_x--+
#                              |
#                              +--reponame_0.git
#                              +--reponame_1.git
#                              +--...
#                              +--reponame_x.git
class SFTPHandle(paramiko.sftp_handle.SFTPHandle):

    def __init__(self, path, flags, attr):

        flags = copy.copy(flags)

        if sys.platform == 'win32':
            flags |= os.O_BINARY

        self._path = path

        self._fobj = os.open(path, flags)

        if flags & os.O_CREAT != 0:
            self.chattr(attr)

        return

    def chattr(self, attr):

        #        print('ca 1')
        #os.chown(self._path, attr.st_uid, attr.st_gid, follow_symlinks=False)
        #        print('ca 2')
        # TODO: fix atleast modes
        #os.chmod(self._path, attr.st_mode, follow_symlinks=False)

        return

    def close(self):
        os.close(self._fobj)

    def read(self, offset, length):
        os.lseek(self._fobj, offset, os.SEEK_SET)
        ret = os.read(self._fobj, length)
        return ret

    def stat(self):
        s = paramiko.sftp_attr.SFTPAttributes.from_stat(
            os.stat(self._path)
            )
        s.filename = os.path.basename(self._path)
        return s

    def write(self, offset, data):
        ret = None
        try:
            os.lseek(self._fobj, offset, os.SEEK_SET)
            os.write(self._fobj, data)
        except:
            logging.exception("Error")
            sys.stderr.flush()
            sys.stdout.flush()
            ret = paramiko.SFTP_FAILURE
        else:
            ret = paramiko.SFTP_OK
        return ret


class SFTPServerInterface(paramiko.sftp_si.SFTPServerInterface):

    def __init__(self, server, ssh_git_host, *largs, **kwargs):
        self._server = server
        self._ssh_git_host = ssh_git_host
        return

    def canonicalize(self, path):
        return org.wayround.utils.path.normpath(path)

    def check_outside(self, path):
        if self._ssh_git_host.check_is_path_outside(path):
            raise ValueError("canonicalize: path outside allowed dir")
        return

    def translate_path(self, path):

        ap = org.wayround.utils.path.abspath(
            org.wayround.utils.path.join(
                self._ssh_git_host.get_working_root_dir(),
                path
                )
            )
        self.check_outside(ap)

        return ap

    def list_folder(self, path):
        #        print("list_folder: {}".format(path))

        path = self.translate_path(path)

        ret = None

        if not os.path.isdir(path):
            ret = paramiko.SFTP_NO_SUCH_FILE

        if ret == None:

            ret = []

            for i in os.listdir(path):
                s = paramiko.sftp_attr.SFTPAttributes.from_stat(
                    os.stat(
                        org.wayround.utils.path.join(path, i),
                        follow_symlinks=False
                        )
                    )
                s.filename = i
                ret.append(s)

        #        print("ret: {}".format(ret))
        return ret

    def lstat(self, path):
        #        print("lstat: {}".format(path))
        path = self.translate_path(path)

        ret = None

        if not os.path.exists(path) and not os.path.islink(path):
            ret = paramiko.SFTP_NO_SUCH_FILE

        if ret == None:

            ret = paramiko.sftp_attr.SFTPAttributes.from_stat(
                os.stat(path, follow_symlinks=False)
                )
            ret.filename = os.path.basename(path)

        #        print("ret: {}".format(ret))
        return ret

    def mkdir(self, path, attr):
        #        print("mkdir: {}, {}".format(path, attr))
        path = self.translate_path(path)

        ret = None
        try:
            os.mkdir(path)
        except:
            ret = paramiko.SFTP_NO_SUCH_FILE
        else:
            ret = paramiko.SFTP_OK

        #        print("ret: {}".format(ret))
        return ret

    def open(self, path, flags, attr):
        #        print("open: {}, {}, {}".format(path, repr(flags), repr(attr))
        #              )
        #        for i in [
        #            'O_RDONLY',
        #            'O_WRONLY',
        #            'O_RDWR',
        #            'O_APPEND',
        #            'O_CREAT',
        #            'O_TRUNC',
        #            'O_EXCL'
        #            ]:
        #            if flags & getattr(os, i) != 0:
        #                print('  {}'.format(i))
        path = self.translate_path(path)

        ret = None

        #if not os.path.exists(path):
        #    if flags & os.O_CREAT == 0:
        #        ret = paramiko.SFTP_NO_SUCH_FILE

        if ret == None:
            ret = SFTPHandle(path, flags, attr)

        #        print("ret: {}".format(ret))
        return ret

    def readlink(self, path):
        #        print("readlink: {}".format(path))
        path = self.translate_path(path)

        ret = None

        if not os.path.exists(path):
            ret = paramiko.SFTP_NO_SUCH_FILE

        if ret == None:
            ret = os.readlink(path)

        #        print("ret: {}".format(ret))
        return ret

    def remove(self, path):
        #        print("remove: {}".format(path))
        path = self.translate_path(path)

        ret = None

        if not os.path.isfile(path) and not os.path.islink(path):
            ret = paramiko.SFTP_NO_SUCH_FILE

        if ret == None:
            try:
                os.unlink(path)
            except:
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

        #        print("ret: {}".format(ret))
        return ret

    def rename(self, oldpath, newpath):
        #        print("rename: {}, {}".format(oldpath, newpath))

        oldpath = self.translate_path(oldpath)
        newpath = self.translate_path(newpath)

        ret = None

        if not os.path.isfile(oldpath):
            ret = paramiko.SFTP_NO_SUCH_FILE

        if os.path.exists(newpath) or os.path.islink(newpath):
            ret = paramiko.SFTP_FAILURE

        if ret == None:
            try:
                os.rename(oldpath, newpath)
            except:
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

        #        print("ret: {}".format(ret))
        return ret

    def rmdir(self, path):
        #        print("rmdir: {}".format(path))
        path = self.translate_path(path)

        ret = None

        if not os.path.isdir(path):
            ret = paramiko.SFTP_NO_SUCH_FILE

        if ret == None:
            try:
                os.rmdir(path)
            except:
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

        #        print("ret: {}".format(ret))
        return ret

    def stat(self, path):
        #        print("stat: {}".format(path))

        path = self.translate_path(path)

        ret = None

        if not os.path.exists(path) and not os.path.islink(path):
            ret = paramiko.SFTP_NO_SUCH_FILE

        if ret == None:

            ret = paramiko.sftp_attr.SFTPAttributes.from_stat(
                os.stat(path, follow_symlinks=True)
                )
            ret.filename = os.path.basename(path)

#        print("ret: {}".format(ret))
        return ret

    def symlink(self, target_path, path):
#        print("symlink: {}, {}".format(target_path, path))

        path = self.translate_path(path)

        ret = None

        if os.path.exists(path) or os.path.islink(path):
            ret = paramiko.SFTP_FAILURE

        if ret == None:
            try:
                os.symlink(target_path, path)
            except:
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

        #        print("ret: {}".format(ret))
        return ret


def channel_exec_cmd(channel, cmd):

    debug = False

    if debug:
        logging.debug("starting: {}".format(cmd))

    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0
        )

    sock_type = 'socket'
    if channel.gettimeout() == 0:
        sock_type = 'socket-nb'

    if debug:
        logging.debug("socket type is: {}".format(sock_type))

    t1 = org.wayround.utils.stream.cat(
        p.stdout,
        channel,
        threaded=True,
        read_method_name='read',
        write_method_name='send',
        read_type='pipe',
        write_type=sock_type,
        exit_on_input_eof=True,
        flush_after_each_write=False,
        flush_on_input_eof=False,
        close_output_on_eof=True,
        descriptor_to_wait_for_input=p.stdout,
        descriptor_to_wait_for_output=None,
        apply_input_seek=False,
        apply_output_seek=False,
        standard_write_method_result=True,
        termination_event=None,
        on_exit_callback=None,
        on_input_read_error=None,
        on_output_write_error=None,
        debug=False,
        verbose=False
        )

    t2 = org.wayround.utils.stream.cat(
        channel,
        p.stdin,
        threaded=True,
        read_method_name='recv',
        write_method_name='write',
        read_type=sock_type,
        write_type='pipe',
        exit_on_input_eof=True,
        flush_after_each_write=False,
        flush_on_input_eof=True,
        close_output_on_eof=True,
        descriptor_to_wait_for_input=None,
        descriptor_to_wait_for_output=None,
        apply_input_seek=False,
        apply_output_seek=False,
        standard_write_method_result=True,
        termination_event=None,
        on_exit_callback=None,
        on_input_read_error=None,
        on_output_write_error=None,
        debug=False,
        verbose=False
        )

    t3 = org.wayround.utils.stream.cat(
        p.stderr,
        channel,
        threaded=True,
        read_method_name='read',
        write_method_name='send_stderr',
        read_type='pipe',
        write_type=sock_type,
        exit_on_input_eof=True,
        flush_after_each_write=False,
        flush_on_input_eof=False,
        close_output_on_eof=True,
        descriptor_to_wait_for_input=p.stdout,
        descriptor_to_wait_for_output=None,
        apply_input_seek=False,
        apply_output_seek=False,
        standard_write_method_result=True,
        termination_event=None,
        on_exit_callback=None,
        on_input_read_error=None,
        on_output_write_error=None,
        debug=False,
        verbose=False
        )

    t1.start()
    t2.start()
    t3.start()

    if debug:
        logging.debug("waiting for program")

    p_res = p.wait()

    channel.send_exit_status(p_res)

    if debug:
        logging.debug("program exited: {}".format(p_res))

    if debug:
        logging.debug("waiting t1")
    t1.join()

    if debug:
        logging.debug("waiting t2")
    t2.join()

    if debug:
        logging.debug("waiting t3")
    t3.join()

    return


class ServerInterface(paramiko.server.ServerInterface):

    def __init__(self, ssh_git_host):

        self._ssh_git_host = ssh_git_host

    def check_outside(self, path):
        return self._ssh_git_host.check_is_path_outside(path)

    def check_auth_publickey(self, username, key):

        ret = paramiko.AUTH_FAILED

        user_dir = self._ssh_git_host.user_get_path(username)

        error = False

        if not isinstance(key, paramiko.rsakey.RSAKey):
            error = True

        if not isinstance(user_dir, str):
            error = True

        if not error:
            if self._ssh_git_host.callbacks['check_key'](username, key):
                ret = paramiko.AUTH_SUCCESSFUL

        return ret

    def check_channel_exec_request(self, channel, command):
        ret = False
        parsed_cmd = shlex.split(command)
        print(
            "check_channel_exec_request: {}, {}\n{}".format(
                channel,
                command,
                parsed_cmd
                )
            )

        cmd = []

        prog = parsed_cmd[0]
        if prog in [
            'git-upload-pack', 'git-receive-pack', 'git-upload-archive'
            ]:

            np = org.wayround.utils.path.join(
                self._ssh_git_host.get_working_root_dir(),
                parsed_cmd[1]
                )
            if self.check_outside(np):
                ret = False
            else:
                cmd = [prog, np]
                ret = True

        if (prog == 'scp'
            and parsed_cmd[1] == '-r'
            and parsed_cmd[2] == '-t'
            and len(parsed_cmd) == 4):

            np = org.wayround.utils.path.join(
                self._ssh_git_host.get_working_root_dir(),
                parsed_cmd[3]
                )
            if self.check_outside(np):
                ret = False
            else:
                cmd = parsed_cmd[:3] + [np]
                ret = True

        if ret == True:

            logging.debug("Starting channel_exec_cmd thread")
            print("exec: {}".format(cmd))
            threading.Thread(
                target=channel_exec_cmd,
                args=(channel, cmd)
                ).start()

        return ret

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_channel_request(self, kind, chanid):
        ret = paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        #        print("check_channel_request({}, {})".format(kind, chanid))
        if kind == 'session':
            ret = paramiko.OPEN_SUCCEEDED
        return ret


class SSHGitHost:

    def __init__(
        self,
        working_root_dir,
        host_addr='localhost',
        host_port='2121',
        host_key_privat_rsa_filename='host_keys/host_rsa'
        ):

        self._socket = None

        self._host_addr = host_addr
        self._host_port = host_port

        # TODO: get realpath or not?
        self._working_root_dir = working_root_dir

        self._host_key_privat_rsa_filename = host_key_privat_rsa_filename
        self._rsa_private_host_key = None

        self._stop_flag = False

        self._acceptor_thread = None

        self.callbacks = None

        # self._server_interface = ServerInterface(self)

        return

    def get_working_root_dir(self):
        return self._working_root_dir

    def check_is_path_outside(self, path):
        ret = False
        if not org.wayround.utils.path.is_subpath(
            path,
            self.get_working_root_dir()
            ):
            ret = True
        return ret

    def get_access_right(
        self, subject_jid, home_level=None, repo_level=None
        ):

        ret = False

        return ret

    def start(self):

        if self._acceptor_thread == None:
            self._acceptor_thread = 1

            self._stop_flag = False

            self._rsa_private_host_key = paramiko.rsakey.RSAKey(
                filename=self._host_key_privat_rsa_filename
                )

            self._socket = socket.socket()
            self._socket.settimeout(0)
            self._socket.bind((self._host_addr, self._host_port))
            self._socket.listen(0)

            self._acceptor_thread = threading.Thread(target=self._acceptor)
            self._acceptor_thread.start()

        return

    def stop(self):
        self._stop_flag = True
        while self._acceptor_thread != None:
            time.sleep(0.2)
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        self._socket = None
        return

    def set_callbacks(self, cbs):
        errors = False
        if cbs != None:

            if not isinstance(cbs, dict):
                raise TypeError("`cbs' can be None or dict")

            for i in ['check_key']:
                if not i in cbs or not callable(cbs[i]):
                    logging.error("`{}' must be in callbacks".format(i))
                    errors = True
            if errors:
                raise ValueError("invalid callback dict")

        if not errors:
            self.callbacks = cbs

        return

    def _acceptor(self):

        accepted = None

        while True:

            accepted = None

            while True:
                if len(select.select([self._socket], [], [], 0.2)[0]) != 0:
                    break
                if self._stop_flag:
                    break

            if self._stop_flag:
                break
            else:

                accepted = self._socket.accept()

            if accepted != None:
                threading.Thread(
                    name="_accepted processor for `{}' from `{}'".format(
                        accepted[0],
                        accepted[1]
                        ),
                    args=(accepted,),
                    target=self._accepted_processor
                    ).start()

        self._acceptor_thread = None

        return

    def _accepted_processor(self, accepted):

        sock = accepted[0]

        paramiko_transport = paramiko.transport.Transport(sock)
        paramiko_transport.add_server_key(self._rsa_private_host_key)
        paramiko_transport.set_subsystem_handler(
            'sftp',
            paramiko.sftp_server.SFTPServer,
            sftp_si=SFTPServerInterface,
            ssh_git_host=self
            )

        paramiko_transport.start_server(
            server=ServerInterface(self)
            )
        return

    def user_validate_name(self, name):
        if not isinstance(name, str):
            raise TypeError("user name value must be str")

        jid_is_invalid = False
        jid = org.wayround.xmpp.core.JID.new_from_str(name)

        if not isinstance(jid, org.wayround.xmpp.core.JID):
            jid_is_invalid = True
        else:
            if not jid.is_bare() and not jid.is_domain():
                jid_is_invalid = True

        if jid_is_invalid:
            raise ValueError(
                "user name must be str containing bare jid or domain"
                )

        return

    def repository_validate_name(self, name):
        if not isinstance(name, str):
            raise TypeError("repository name value must be str")

        name_is_invalid = False

        if len(name) < 1:
            name_is_invalid = True

        if name.isspace():
            name_is_invalid = True

        if name.startswith(' ') or name.endswith(' '):
            name_is_invalid = True

        if name_is_invalid:
            raise ValueError(
                "repository name must be non-empty a str not starting and"
                "not ending with spaces"
                )

        return

    def user_list(self):

        path = self.get_working_root_dir()

        dirs = os.listdir(path)

        ret = []

        for i in dirs:
            joined = org.wayround.utils.path.join(path, i)

            if os.path.isdir(joined):
                ret.append(i)

        ret.sort()

        return ret

    def user_is_exists(self, user_name):

        self.user_validate_name(user_name)

        return os.path.isdir(self.user_get_path(user_name))

    def user_create(self, user_name):

        self.user_validate_name(user_name)

        ret = 0

        if self.user_is_exists(user_name):
            ret = 2
        else:
            path = self.user_get_path(user_name)
            if not os.path.isdir(path):
                try:
                    os.makedirs(path)
                except:
                    pass
            if not self.user_is_exists(user_name):
                ret = 1
        return ret

    def user_delete(self, user_name):

        self.user_validate_name(user_name)

        ret = 0
        if not self.user_is_exists(user_name):
            ret = 2
        else:
            try:
                shutil.rmtree(self.user_get_path(user_name))
            except:
                pass
            if self.user_is_exists(user_name):
                ret = 1
        return ret

    def user_get_path(self, user_name):

        self.user_validate_name(user_name)

        ret = org.wayround.utils.path.join(
            self._working_root_dir,
            user_name
            )

        return ret

    def repository_list(self, user_name):

        self.user_validate_name(user_name)

        ret = None

        if self.user_is_exists(user_name):
            path = self.user_get_path(user_name)
            dirs = os.listdir(path)

            ret = []

            for i in dirs:
                joined = org.wayround.utils.path.join(path, i)

                if os.path.isdir(joined):
                    ret.append(i)

            ret.sort()

        return ret

    def repository_get_path(self, user_name, repository_name):

        self.user_validate_name(user_name)
        self.repository_validate_name(repository_name)

        ret = org.wayround.utils.path.join(
            self.user_get_path(user_name),
            repository_name
            )

        return ret

    def repository_is_exists(self, user_name, repository_name):

        self.user_validate_name(user_name)
        self.repository_validate_name(repository_name)

        return os.path.isdir(
            self.repository_get_path(user_name, repository_name)
            )

    def repository_create(self, user_name, repository_name):

        self.user_validate_name(user_name)
        self.repository_validate_name(repository_name)

        ret = 0

        if self.repository_is_exists(user_name, repository_name):
            ret = 1
        else:
            if not self.user_is_exists(user_name):
                ret = 2
            else:
                path = self.repository_get_path(user_name, repository_name)
                p = subprocess.Popen(['git', 'init', '--bare', path])
                ret = p.wait()

        return ret

    def repository_delete(self, user_name, repository_name):

        self.user_validate_name(user_name)
        self.repository_validate_name(repository_name)

        ret = 0

        if not self.repository_is_exists(user_name, repository_name):
            ret = 1
        else:
            if not self.user_is_exists(user_name):
                ret = 2
            else:
                try:
                    shutil.rmtree(
                        self.repository_get_path(user_name, repository_name)
                        )
                except:
                    pass

                if self.repository_is_exists(user_name, repository_name):
                    ret = 3

        return ret
