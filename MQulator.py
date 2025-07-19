#!/usr/bin/env python3
# MQulator - IBM MQ browsing tool
#
# Author: Garland Glessner <gglessner@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import jpype
import jpype.imports
import time
import os
import sys
from itertools import product

VERSION = "1.0.0"

if __name__ == "__main__":
    banner = r"""
  __  __  ___       _      _           
 |  \/  |/ _ \ _  _| |__ _| |_ ___ _ _ 
 | |\/| | (_) | || | / _` |  _/ _ \ '_|
 |_|  |_|\__\_\\_,_|_\__,_|\__\___/_|
"""
    print(banner)
    print(f"Version: {VERSION}\n") 

# Argument parsing
parser = argparse.ArgumentParser(description='MQulator: IBM MQ browsing tool')
parser.add_argument('--servers', required=True, help='Path to server.txt')
parser.add_argument('--qms', required=True, help='Path to qm.txt')
parser.add_argument('--channels', required=True, help='Path to channel.txt')
parser.add_argument('--queues', required=True, help='Path to queue.txt')
parser.add_argument('--certs', required=True, help='Path to certs.txt')
parser.add_argument('--cipher', default='TLS_RSA_WITH_AES_256_CBC_SHA256', help='Cipher suite for TLS (default: TLS_RSA_WITH_AES_256_CBC_SHA256)')
parser.add_argument('--browse-timeout', type=float, default=5.0, help='Max seconds to browse each queue (default: 5.0)')
args = parser.parse_args()

# JAR paths
ibm_mq_jar = os.path.abspath('./lib/com.ibm.mq.allclient-9.4.1.0.jr')
json_jar = os.path.abspath('./lib/json-20240303.jar')

# Cipher suite
cipher_suite = args.cipher

# Read input files
def read_lines(path):
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

servers = read_lines(args.servers)
qms = read_lines(args.qms)
channels = read_lines(args.channels)
queues = read_lines(args.queues)
certs = [tuple(line.split('|', 1)) for line in read_lines(args.certs)]

# Start JVM if not already started
if not jpype.isJVMStarted():
    jpype.startJVM(classpath=[ibm_mq_jar, json_jar])

# Import Java classes
from com.ibm.mq import MQQueueManager
from com.ibm.mq.constants import CMQC
from java.util import MQEnvironment, MQException

def try_browse(server, cert, qm, channel, queue):
    password, certfile = cert
    host, port = server.split(':')
    port = int(port)
    print(f"Connecting: server={server}, cert={certfile}, qm={qm}, channel={channel}, queue={queue}")
    try:
        # Set up MQ environment
        jpype.java.lang.System.setProperty("javax.net.ssl.keyStore", certfile)
        jpype.java.lang.System.setProperty("javax.net.ssl.keyStorePassword", password)
        jpype.java.lang.System.setProperty("javax.net.ssl.keyStoreType", "JKS")
        jpype.java.lang.System.setProperty("javax.net.ssl.trustStore", certfile)
        jpype.java.lang.System.setProperty("javax.net.ssl.trustStorePassword", password)
        jpype.java.lang.System.setProperty("javax.net.ssl.trustStoreType", "JKS")
        
        MQEnvironment.hostname = host
        MQEnvironment.port = port
        MQEnvironment.channel = channel
        MQEnvironment.sslCipherSuite = cipher_suite

        # Connect
        qmgr = MQQueueManager(qm)
        print(f"Connected to {qm} on {server} with channel {channel} and cert {certfile}")

        # Open queue for browse
        open_opts = CMQC.MQOO_BROWSE | CMQC.MQOO_INPUT_SHARED
        queue_obj = qmgr.accessQueue(queue, open_opts)
        print(f"Browsing queue: {queue}")

        # Browse all messages using BROWSE_FIRST then BROWSE_NEXT with NO_WAIT, with timeout
        msg_count = 0
        MQMessage = jpype.JClass('com.ibm.mq.MQMessage')
        MQGetMessageOptions = jpype.JClass('com.ibm.mq.MQGetMessageOptions')
        gmo = MQGetMessageOptions()
        gmo.options = CMQC.MQGMO_BROWSE_FIRST | CMQC.MQGMO_NO_WAIT
        mqmsg = MQMessage()
        start_time = time.time()
        try:
            queue_obj.get(mqmsg, gmo)
            msg_count += 1
            print(f"Message {msg_count}: {mqmsg.readString(mqmsg.getDataLength())}")
            # Now loop for next messages
            while True:
                if time.time() - start_time > args.browse_timeout:
                    print(f"Browse timeout ({args.browse_timeout} seconds) reached.")
                    break
                gmo.options = CMQC.MQGMO_BROWSE_NEXT | CMQC.MQGMO_NO_WAIT
                mqmsg = MQMessage()
                queue_obj.get(mqmsg, gmo)
                msg_count += 1
                print(f"Message {msg_count}: {mqmsg.readString(mqmsg.getDataLength())}")
        except Exception as e:
            if msg_count == 0:
                print("No messages found.")
            # else, end of queue reached
        queue_obj.close()
        qmgr.disconnect()
        print(f"Disconnected from {qm} on {server}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

# Iterate all combinations
for server, cert, qm, channel, queue in product(servers, certs, qms, channels, queues):
    try_browse(server, cert, qm, channel, queue)

print("==========================================\nAll combinations processed.") 