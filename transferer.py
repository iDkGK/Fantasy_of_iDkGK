import binascii
import hashlib
import subprocess
import sys
import time
from argparse import ArgumentParser
from subprocess import Popen

if __name__ == "__main__":
    parser = ArgumentParser()
    mutex_group = parser.add_mutually_exclusive_group()
    mutex_group.add_argument(
        "-s",
        "--send",
        type=str,
        default="",
        help="Run this script in sending mode",
    )
    mutex_group.add_argument(
        "-r",
        "--receive",
        type=str,
        default="",
        help="Run this script in receiving mode",
    )
    parser.add_argument(
        "-sa",
        "--server-address",
        type=str,
        required=True,
        help="Specify username and server address",
    )
    parser.add_argument(
        "-bs",
        "--block-size",
        type=int,
        default=1024,
        help="Specify block size per IO during transfer",
    )
    parser.add_argument(
        "-tc",
        "--transfer-code",
        type=str,
        required=True,
        help="Specify 6-digit transfer PIN for handshaking",
    )
    arguments = parser.parse_args()

    TRANS_MODE = "send" if arguments.send else "receive" if arguments.receive else ""
    TRANS_FILE = arguments.send or arguments.receive
    BLOCK_SIZE = arguments.block_size

    SSH_COMMAND = [
        "ssh",
        "-o" "PubkeyAuthentication=no",
        "-T",
        arguments.server_address,
    ]
    TRANS_PIPE = "/tmp/.transferer_pipe_%s" % format(
        binascii.crc32(arguments.transfer_code.encode()), "02x"
    )

    STATUS_NUL = "nul"
    STATUS_SOT = "sot"
    STATUS_SOF = "sof"
    STATUS_EOB = "eob"
    STATUS_EOF = "eof"
    STATUS_SOM = "som"
    STATUS_EOM = "eom"
    STATUS_EOT = "eot"

    """
    Named Pipe Data Sequence:
    STATUS_SOT
        STATUS_SOF
            BLOCK_DATA of BLOCK_SIZE
            STATUS_EOB
            BLOCK_DATA of BLOCK_SIZE
            STATUS_EOB
            ...
            BLOCK_DATA of BLOCK_SIZE
            STATUS_EOB
        STATUS_EOF
        STATUS_SOM
            MD5_DATA of file
        STATUS_EOM
    STATUS_EOT
    """

    with Popen(
        SSH_COMMAND,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        universal_newlines=True,
    ) as ssh_client:
        if ssh_client.stdin is None:
            print("Unable to open stdin for ssh client!")
            sys.exit(255)
        if ssh_client.stdout is None:
            print("Unable to open stdout for ssh client!")
            sys.exit(255)
        if TRANS_MODE == "send":
            ssh_client.stdin.write(
                "rm -f %s && mkfifo %s || true\n" % (TRANS_PIPE, TRANS_PIPE)
            )
            ssh_client.stdin.write("echo %s > %s || true\n" % (STATUS_SOT, TRANS_PIPE))
            ssh_client.stdin.write("echo %s > %s || true\n" % (STATUS_SOF, TRANS_PIPE))
            md5_hasher = hashlib.md5()
            file_size = 0
            with open(TRANS_FILE, "rb") as file:
                while True:
                    block_data = file.read(BLOCK_SIZE)
                    if not block_data:
                        ssh_client.stdin.write(
                            "echo %s > %s || true\n" % (STATUS_EOF, TRANS_PIPE)
                        )
                        break
                    file_size += len(block_data)
                    md5_hasher.update(block_data)
                    hex_data = binascii.hexlify(block_data).decode()
                    ssh_client.stdin.write(
                        "echo %s > %s || true\n" % (hex_data, TRANS_PIPE)
                    )
                    ssh_client.stdin.write(
                        "echo %s > %s || true\n" % (STATUS_EOB, TRANS_PIPE)
                    )
                md5 = md5_hasher.hexdigest()
            ssh_client.stdin.write("echo %s > %s || true\n" % (STATUS_SOM, TRANS_PIPE))
            ssh_client.stdin.write("echo %s > %s || true\n" % (md5, TRANS_PIPE))
            ssh_client.stdin.write("echo %s > %s || true\n" % (STATUS_EOM, TRANS_PIPE))
            ssh_client.stdin.write("echo %s > %s || true\n" % (STATUS_EOT, TRANS_PIPE))
            ssh_client.stdin.write(
                "kill -9 $(ps -aux | grep %s | awk -F ' ' '{print $2}') || true\n"
                % TRANS_PIPE
            )
            ssh_client.stdin.write("rm -f %s || true\n" % TRANS_PIPE)
            print("Sending file of size %d bytes complete." % file_size)
            print("Script will automatically exit after file data is fully received.")
        elif TRANS_MODE == "receive":
            ssh_client.stdin.write("tail -f %s || true\n" % TRANS_PIPE)
            time_start = time.time()
            time_transfer = time.perf_counter_ns()
            md5_hasher = hashlib.md5()
            file_size = 0
            transfer_status = STATUS_NUL
            receive_data = ""
            md5_data = ""
            with open(TRANS_FILE, "wb") as file:
                while True:
                    receive_data += ssh_client.stdout.read(1)
                    last_three_bytes = receive_data[-3:]
                    if last_three_bytes in (
                        STATUS_SOT,
                        STATUS_SOF,
                        STATUS_EOB,
                        STATUS_EOF,
                        STATUS_SOM,
                        STATUS_EOM,
                        STATUS_EOT,
                    ):
                        transfer_status = last_three_bytes
                    if transfer_status == STATUS_SOT:
                        print(
                            "\x1b[sStart receiving file data from remote data queue and saving it to file %s.\x1b[u"
                            % TRANS_FILE,
                            end="",
                            flush=True,
                        )
                    if transfer_status == STATUS_SOF:
                        print("")
                        time_transfer = time.perf_counter_ns()
                        transfer_status = STATUS_NUL
                        receive_data = ""
                    if transfer_status == STATUS_EOB:
                        block_data = binascii.unhexlify(
                            receive_data.strip().rstrip(transfer_status).strip()
                        )
                        block_size = len(block_data)
                        file_size += block_size
                        md5_hasher.update(block_data)
                        file.write(block_data)
                        print(
                            "\x1b[sReceiving file data at speed %.2f KB/s\x1b[u"
                            % (
                                1e6
                                * block_size
                                / (time.perf_counter_ns() - time_transfer)
                            ),
                            end="",
                            flush=True,
                        )
                        time_transfer = time.perf_counter_ns()
                        transfer_status = STATUS_NUL
                        receive_data = ""
                    if transfer_status == STATUS_EOF:
                        pass
                    if transfer_status == STATUS_SOM:
                        transfer_status = STATUS_NUL
                        receive_data = ""
                    if transfer_status == STATUS_EOM:
                        md5_data = receive_data.strip().rstrip(transfer_status).strip()
                        transfer_status = STATUS_NUL
                        receive_data = ""
                    if transfer_status == STATUS_EOT:
                        break
            md5 = md5_hasher.hexdigest()
            if md5_data == md5:
                print(
                    "\nReceiving file of %d bytes completed in %.1fs."
                    % (file_size, time.time() - time_start)
                )
            else:
                print("\nInvalid file MD5!\nRemote: %s\nLocal: %s." % (md5_data, md5))
