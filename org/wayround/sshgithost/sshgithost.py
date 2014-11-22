
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
        # os.chown(self._path, attr.st_uid, attr.st_gid, follow_symlinks=False)
        #        print('ca 2')
        # TODO: fix atleast modes
        # os.chmod(self._path, attr.st_mode, follow_symlinks=False)

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
            ret = paramiko.SFTP_FAILURE
        else:
            ret = paramiko.SFTP_OK
        return ret


class SFTPServerInterface(paramiko.sftp_si.SFTPServerInterface):

    def __init__(
            self,
            server, ssh_git_host, transport,
            *largs, **kwargs
            ):
        """
        :param paramiko.sftp_server.SFTPServer server:
        :param SSHGitHost ssh_git_host:
        :param paramiko.transport.Transport transport:
        """
        self._server = server
        self._ssh_git_host = ssh_git_host
        self._transport = transport
        return

    def check_outside(self, path):
        return self._ssh_git_host.check_is_path_outside(path)

    def check_outside_real(self, path):
        return self._ssh_git_host.check_is_path_outside_real(path)

    def check_permission(self, what, path):
        return self._ssh_git_host.check_permission(
            self._transport.get_username(), what, path
            )

    def translate_path(self, path):

        ap = org.wayround.utils.path.abspath(
            org.wayround.utils.path.join(
                self._ssh_git_host.get_working_root_dir(),
                path
                )
            )

        return ap

    def canonicalize(self, path):
        return org.wayround.utils.path.normpath(path)

    def list_folder(self, path):

        ret = None

        path = self.translate_path(path)
        path = org.wayround.utils.path.realpath(path)

        if self.check_outside_real(path):
            ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if not self.check_permission('can_read', path):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if not os.path.isdir(path):
                ret = paramiko.SFTP_NO_SUCH_FILE

        if ret is None:

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

        return ret

    def lstat(self, path):

        ret = None

        path = self.translate_path(path)

        path_paths = org.wayround.utils.path.file_paths(path)

        if ret is None:
            if self.check_outside_real(path_paths['abs_dir_real']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not os.path.islink(path_paths['abs_full']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not os.path.exists(path_paths['abs_full']):
                ret = paramiko.SFTP_NO_SUCH_FILE

        if ret is None:
            if not self.check_permission(
                    'can_read',
                    path_paths['abs_dir_real_full']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:

            ret = paramiko.sftp_attr.SFTPAttributes.from_stat(
                os.stat(
                    path_paths['abs_dir_real_full'],
                    follow_symlinks=False
                    )
                )
            ret.filename = abs_base

        return ret

    def mkdir(self, path, attr):

        ret = None

        path = self.translate_path(path)

        path_paths = org.wayround.utils.path.file_paths(path)

        if self.check_outside_real(path_paths['abs_dir_real']):
            ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not self.check_permission(
                    'can_write',
                    path_paths['abs_dir_real']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            try:
                os.mkdir(path_paths['abs_dir_real_full'])
            except:
                ret = paramiko.SFTP_NO_SUCH_FILE
            else:
                ret = paramiko.SFTP_OK

        return ret

    def open(self, path, flags, attr):

        ret = None

        # logging.debug(
        #   "==xxxxx=> open params: {}, {}, {}".format(
        #      repr(path),
        #     repr(bin(flags)),
        #    repr(attr)
        #   )
        #)

        flags_f = flags
        for i in [
                os.O_RDONLY,
                os.O_WRONLY,
                os.O_RDWR,
                os.O_APPEND,
                os.O_CREAT,
                os.O_EXCL,
                os.O_TRUNC
                ]:
            flags_f &= ~i

        if flags_f != 0:
            logging.error(
                "unknown file open flags supplyed: {}".format(flags)
                )
            ret = paramiko.SFTP_OP_UNSUPPORTED

        if ret is None:
            dir_mode = 'read'
            file_mode = 'read'

            for i in [
                    os.O_WRONLY,
                    os.O_RDWR,
                    os.O_APPEND,
                    os.O_CREAT,
                    os.O_EXCL,
                    os.O_TRUNC
                    ]:
                if flags & i != 0:
                    file_mode = 'write'

            if flags & os.O_WRONLY != 0:
                dir_mode = 'write'

            path = self.translate_path(path)

            path_paths = org.wayround.utils.path.file_paths(path)

        if ret is None:
            if self.check_outside_real(path_paths['real_full']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if dir_mode == 'write':
                if not self.check_permission(
                        'can_write',
                        path_paths['real_dir']
                        ):
                    ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if not self.check_permission(
                    'can_{}'.format(file_mode),
                    path_paths['real_full']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            ret = SFTPHandle(path_paths['real_full'], flags, attr)

        return ret

    def readlink(self, path):

        ret = None

        path = self.translate_path(path)

        path_paths = org.wayround.utils.path.file_paths(path)

        if ret is None:
            if self.check_outside_real(path_paths['abs_dir_real']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not os.path.islink(path_paths['abs_full']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not self.check_permission('can_read', path_paths['abs_full']):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            ret = os.readlink(path_paths['abs_full'])

        return ret

    def remove(self, path):

        ret = None

        path = self.translate_path(path)

        path_paths = org.wayround.utils.path.file_paths(path)

        if self.check_outside_real(path_paths['abs_dir_real']):
            ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not self.check_permission(
                    'can_write',
                    path_paths['abs_dir_real']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if not os.path.islink(path_paths['abs_dir_real_full']):
                if not os.path.isfile(path_paths['abs_dir_real_full']):
                    ret = paramiko.SFTP_FAILURE

        if ret is None:
            try:
                os.unlink(path_paths['abs_dir_real_full'])
            except:
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

        return ret

    def rename(self, oldpath, newpath):

        ret = None

        oldpath = self.translate_path(oldpath)
        newpath = self.translate_path(newpath)

        oldpath_paths = org.wayround.utils.path.file_paths(oldpath)
        newpath_paths = org.wayround.utils.path.file_paths(newpath)

        if ret is None:
            if self.check_outside_real(oldpath_paths['abs_dir_real_full']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if self.check_outside_real(newpath_paths['abs_dir_real_full']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not self.check_permission(
                    'can_write',
                    oldpath_paths['abs_dir_real']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if not self.check_permission(
                    'can_write',
                    newpath_paths['abs_dir_real']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            try:
                os.rename(
                    oldpath_paths['abs_dir_real_full'],
                    newpath_paths['abs_dir_real_full']
                    )
            except:
                logging.exception(
                    "can't rename file `{}' ->\n   `{}'".format(
                        oldpath,
                        newpath
                        )
                    )
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

        return ret

    def rmdir(self, path):

        ret = None

        path = self.translate_path(path)

        path_paths = org.wayround.utils.path.file_paths(path)

        if self.check_outside_real(path_paths['abs_dir_real_full']):
            ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not self.check_permission(
                    'can_write',
                    path_paths['abs_dir_real_full']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if os.path.islink(path_paths['abs_dir_real_full']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not os.path.isdir(path_paths['abs_dir_real_full']):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            try:
                os.rmdir(path_paths['abs_dir_real_full'])
            except:
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

        return ret

    def stat(self, path):

        ret = None

        path = self.translate_path(path)

        path_paths = org.wayround.utils.path.file_paths(path)

        if self.check_outside_real(path_paths['real_full']):
            ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not self.check_permission(
                    'can_read',
                    path_paths['real_full']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if (not os.path.exists(path_paths['real_full'])
                    and not os.path.islink(path_paths['real_full'])):
                ret = paramiko.SFTP_NO_SUCH_FILE

        if ret is None:

            ret = paramiko.sftp_attr.SFTPAttributes.from_stat(
                os.stat(path_paths['real_full'], follow_symlinks=True)
                )
            ret.filename = path_paths['abs_base']

        return ret

    def symlink(self, target_path, path):

        ret = None

        path = self.translate_path(path)

        path_paths = org.wayround.utils.path.file_paths(path)

        if self.check_outside_real(path_paths['abs_dir_real']):
            ret = paramiko.SFTP_FAILURE

        if ret is None:
            if not self.check_permission(
                    'can_write',
                    path_paths['abs_dir_real']
                    ):
                ret = paramiko.SFTP_PERMISSION_DENIED

        if ret is None:
            if (os.path.exists(path_paths['abs_dir_real_full'])
                    or os.path.islink(path_paths['abs_dir_real_full'])):
                ret = paramiko.SFTP_FAILURE

        if ret is None:
            try:
                os.symlink(
                    target_path,
                    path_paths['abs_dir_real_full']
                    )
            except:
                ret = paramiko.SFTP_FAILURE
            else:
                ret = paramiko.SFTP_OK

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

    sock_type = 'sync'
    sock_selectable = True
    if channel.gettimeout() == 0:
        sock_type = 'async'
        sock_selectable = False

    if debug:
        logging.debug("socket type is: {}".format(sock_type))

    t1 = org.wayround.utils.stream.cat(
        p.stdout,
        channel,
        threaded=True,
        read_method_name='read',
        write_method_name='send',
        read_type='sync',
        read_selectable=True,
        write_type=sock_type,
        write_selectable=sock_selectable,
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
        read_selectable=sock_selectable,
        write_type='sync',
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
        read_type='sync',
        read_selectable=True,
        write_type=sock_type,
        write_selectable=sock_selectable,
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

    def __init__(self, ssh_git_host, transport):
        """
        :param SSHGitHost ssh_git_host:
        :param paramiko.transport.Transport transport:
        """

        self._ssh_git_host = ssh_git_host
        self._transport = transport

    def check_outside(self, path):
        return self._ssh_git_host.check_is_path_outside(path)

    def check_outside_real(self, path):
        return self._ssh_git_host.check_is_path_outside_real(path)

    def get_levels(self, path):
        return get_levels(self._ssh_git_host.get_working_root_dir(), path)

    # def check_permission(self, what, path, must_be_repository=False):

        # ret = False

        # if must_be_repository:

        #  levels = self.get_levels(path)
        # if levels[1] is None:
        #    logging.debug("not a repository - no permission")
        #   ret = False
        # else:
        #   ret = self._ssh_git_host.check_permission(
        #      self._transport.get_username(), what, path
        #     )
        # return ret

    def check_permission(self, what, path):
        return self._ssh_git_host.check_permission(
            self._transport.get_username(), what, path
            )

    def check_auth_publickey(self, username, key):

        ret = paramiko.AUTH_FAILED

        user_dir = self._ssh_git_host.home_get_path(username)

        error = False

        if not isinstance(key, paramiko.rsakey.RSAKey):
            error = True

        if not isinstance(user_dir, str):
            error = True

        if not error:
            if self._ssh_git_host.callbacks['check_key'](username, key):
                ret = paramiko.AUTH_SUCCESSFUL
                # print("user is: {}".format(username))

        return ret

    def check_channel_exec_request(self, channel, command):
        ret = False
        parsed_cmd = shlex.split(command)
        logging.debug(
            "check_channel_exec_request: {}, {}\n{}".format(
                channel,
                command,
                parsed_cmd
                )
            )

        cmd = []

        prog = parsed_cmd[0]
        if prog in [
                'git-receive-pack',
                'git-upload-pack',
                'git-upload-archive'
                ]:

            np = org.wayround.utils.path.join(
                self._ssh_git_host.get_working_root_dir(),
                parsed_cmd[1]
                )
            if self.check_outside_real(np):
                ret = False
            else:

                perm = False

                if prog in [
                        'git-upload-pack',
                        'git-upload-archive'
                        ]:

                    perm = self.check_permission(
                        'can_read', np, must_be_repo=True
                        )

                elif prog == 'git-receive-pack':

                    perm = self.check_permission(
                        'can_write', np
                        )

                else:
                    raise Exception("programming error")

                if not perm:
                    ret = False
                else:

                    cmd = [prog, np]
                    ret = True

        if prog == 'scp':

            error = True
            pkmd = []
            pth = ''

            params = parsed_cmd[1:-1]
            pth = parsed_cmd[-1]

            method = None
            if '-t' in params:
                method = 'can_write'
                error = False
            elif '-f' in params:
                method = 'can_read'
                error = False
            else:
                error = True
                ret = False

            if not error:
                while pth.startswith('/'):
                    pth = pth[1:]

                np = org.wayround.utils.path.join(
                    self._ssh_git_host.get_working_root_dir(),
                    pth
                    )
                if self.check_outside_real(np):
                    ret = False
                else:
                    if self.check_permission(method, np):
                        cmd = ['scp'] + params + [np]
                        ret = True
                    else:
                        logging.debug(
                            "no `{}' permission to `{}'".format(method, np)
                            )

        if ret is True:

            logging.debug("Starting channel_exec_cmd thread")
            thr = threading.Thread(
                target=channel_exec_cmd,
                args=(channel, cmd)
                )
            thr.start()
            # thr.join()

        return ret

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_channel_request(self, kind, chanid):
        ret = paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
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

        self._working_root_dir = \
            org.wayround.utils.path.realpath(working_root_dir)

        self._host_key_privat_rsa_filename = host_key_privat_rsa_filename
        self._rsa_private_host_key = None

        self._stop_flag = False

        self._acceptor_thread = None

        self.callbacks = None

        return

    def get_working_root_dir(self):
        return self._working_root_dir

    def check_is_path_outside(self, path):
        return not org.wayround.utils.path.is_subpath(
            path,
            self.get_working_root_dir()
            )

    def check_is_path_outside_real(self, path):
        return not org.wayround.utils.path.is_subpath_real(
            path,
            self.get_working_root_dir()
            )

    def check_permission(self, subject_jid, what, path):

        home_level, repo_level, rest = self.get_levels(path)

        ret = self.callbacks['check_permission'](
            subject_jid,
            what,
            home_level,
            repo_level
            )

        return ret

    def get_levels(self, path):
        return get_levels(self.get_working_root_dir(), path)

    def start(self):

        if self._acceptor_thread is None:
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
        while self._acceptor_thread is not None:
            time.sleep(0.2)
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        self._socket = None
        return

    def set_callbacks(self, cbs):
        errors = False
        if cbs is not None:

            if not isinstance(cbs, dict):
                raise TypeError("`cbs' can be None or dict")

            for i in ['check_key', 'check_permission']:
                if i not in cbs or not callable(cbs[i]):
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

            if accepted is not None:
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
            ssh_git_host=self,
            transport=paramiko_transport
            )

        paramiko_transport.start_server(
            server=ServerInterface(
                self,
                paramiko_transport
                )
            )
        return

    def home_validate_name(self, name):

        jid_is_invalid = False

        try:
            jid = org.wayround.xmpp.core.jid_to_bare(name)
        except:
            raise

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

    def home_list(self):

        path = self.get_working_root_dir()

        dirs = os.listdir(path)

        ret = []

        for i in dirs:
            joined = org.wayround.utils.path.join(path, i)

            if os.path.isdir(joined):
                ret.append(i)

        ret.sort()

        return ret

    def home_is_exists(self, home):

        self.home_validate_name(home)

        return os.path.isdir(self.home_get_path(home))

    def home_create(self, home):

        self.home_validate_name(home)

        ret = 0

        if self.home_is_exists(home):
            ret = 2
        else:
            path = self.home_get_path(home)
            if not os.path.isdir(path):
                try:
                    os.makedirs(path)
                except:
                    pass
            if not self.home_is_exists(home):
                ret = 1
        return ret

    def home_delete(self, home):

        self.home_validate_name(home)

        ret = 0
        if not self.home_is_exists(home):
            ret = 2
        else:
            try:
                shutil.rmtree(self.home_get_path(home))
            except:
                pass
            if self.home_is_exists(home):
                ret = 1
        return ret

    def home_get_path(self, home):

        self.home_validate_name(home)

        ret = org.wayround.utils.path.join(
            self._working_root_dir,
            home
            )

        return ret

    def repository_list(self, home):

        self.home_validate_name(home)

        ret = None

        if self.home_is_exists(home):
            path = self.home_get_path(home)
            dirs = os.listdir(path)

            ret = []

            for i in dirs:
                joined = org.wayround.utils.path.join(path, i)

                if os.path.isdir(joined):
                    ret.append(i)

            ret.sort()

        return ret

    def repository_get_path(self, home, repository):

        self.home_validate_name(home)
        self.repository_validate_name(repository)

        ret = org.wayround.utils.path.join(
            self.home_get_path(home),
            repository
            )

        return ret

    def repository_is_exists(self, home, repository):

        self.home_validate_name(home)
        self.repository_validate_name(repository)

        return os.path.isdir(
            self.repository_get_path(home, repository)
            )

    def repository_create(self, home, repository):

        self.home_validate_name(home)
        self.repository_validate_name(repository)

        ret = 0

        if self.repository_is_exists(home, repository):
            ret = 1
        else:
            if not self.home_is_exists(home):
                ret = 2
            else:
                path = self.repository_get_path(home, repository)
                p = subprocess.Popen(['git', 'init', '--bare', path])
                ret = p.wait()

        return ret

    def repository_delete(self, home, repository):

        self.home_validate_name(home)
        self.repository_validate_name(repository)

        ret = 0

        if not self.repository_is_exists(home, repository):
            ret = 1
        else:
            if not self.home_is_exists(home):
                ret = 2
            else:
                try:
                    shutil.rmtree(
                        self.repository_get_path(home, repository)
                        )
                except:
                    pass

                if self.repository_is_exists(home, repository):
                    ret = 3

        return ret


def get_levels(root_path, path):

    if not isinstance(root_path, str):
        raise TypeError("`root_path' must be str")

    if not isinstance(path, str):
        raise TypeError("`path' must be str")

    sub_path = org.wayround.utils.path.split(
        org.wayround.utils.path.get_subpath(
            root_path,
            path
            )
        )

    home_level = None
    repo_level = None
    rest = None

    len_sub_path = len(sub_path)
    if len_sub_path > 0:
        home_level = sub_path[0]

    if len_sub_path > 1:
        repo_level = sub_path[1]
        rest = sub_path[2:]

    return home_level, repo_level, rest


def check_level_parameters_validness(home_level, repo_level, rest):

    if (
            (home_level is None and repo_level is None and rest is None)
            or
            (home_level is not None and repo_level is None and rest is None)
            or
            (home_level is not None and repo_level is not None and rest is None)
            or
            (home_level is not None and repo_level is not None and rest is not None)
            ):
        pass
    else:
        raise ValueError("Invalid parameter values combination")
    return


def join_levels(home_level, repo_level, rest):

    check_level_parameters_validness(home_level, repo_level, rest)

    path = '/'

    for i in [home_level, repo_level, rest]:
        if i is not None:
            if not path.endswith('/'):
                path += '/'
            path += i.strip('/')

    return path
