
import socket
import threading
import time
import select


# working root dir structure:
#
# working_root_dir-+
#                  |
#                  +--user_0
#                  +--user_1
#                  +--...
#                  +--user_x--+
#                             |
#                             +--settings--+
#                             |            |
#                             |            +--public ssh key
#                             |
#                             +--repositories--+
#                                              |
#                                              +--reponame_0
#                                              +--reponame_1
#                                              +--...
#                                              +--reponame_x--+
#                                                             |
#                                                             +--.git
#                                                             +--settings


class SSHGitHost:

    def __init__(
        self,
        working_root_dir,
        authenticator_callback,
        host_addr='localhost',
        host_port='2121'
        ):

        self._socket = None

        self._host_addr = host_addr
        self._host_port = host_port

        self._stop_flag = False

        self._acceptor_thread = None

        return

    def start(self):

        self._stop_flag = False

        self._socket = socket.socket()
        self._socket.bind((self._host_addr, self._host_port))
        self._socket.listen(0)
        return

    def stop(self):
        self._stop_flag = True
        while self._acceptor_thread != None:
            time.sleep(0.2)
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
                    )

        self._acceptor_thread = None

        return

    def _accepted_processor(self, accepted):
        print(
            "NOT IMPLIMENTED: process connection `{}' from `{}'".format(
                accepted[0],
                accepted[1]
                )
            )
        return

    def user_list(self):
        return

    def user_create(self, name):
        return

    def user_delete(self, name):
        return

    def user_set_enabled(self, name, value):
        return

    def user_get_enabled(self, name):
        return

    def repository_list(self, user_name):
        return

    def repository_create(self, user_name, name):
        return

    def repository_delete(self, user_name, name):
        return
