#!/usr/bin/env python3
# MQwrite - Write raw messages from a file to an IBM MQ queue
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
import os
import sys
import getpass

parser = argparse.ArgumentParser(description='MQwrite: Write raw messages from a file to an IBM MQ queue')
parser.add_argument('--keystore', required=True, help='Path to JKS keystore file')
parser.add_argument('--truststore', help='Path to JKS truststore file (defaults to keystore if not provided)')
parser.add_argument('--server', required=True, help='Server in host:port format')
parser.add_argument('--qm', required=True, help='Queue manager name')
parser.add_argument('--channel', required=True, help='Channel name')
parser.add_argument('--queue', required=True, help='Queue name')
parser.add_argument('--ciphersuite', default='TLS_RSA_WITH_AES_256_CBC_SHA256', help='TLS cipher suite (default: TLS_RSA_WITH_AES_256_CBC_SHA256)')
parser.add_argument('--file', required=True, help='File containing raw messages to write (as produced by MQbrowse.py)')
args = parser.parse_args()

# Use keystore as truststore if not provided
truststore = args.truststore if args.truststore else args.keystore

password = getpass.getpass('Enter JKS password (used for both keystore and truststore): ')

# JAR paths (assume same as MQulator)
ibm_mq_jar = os.path.abspath('./lib/com.ibm.mq.allclient-9.4.1.0.jar')
json_jar = os.path.abspath('./lib/json-20240303.jar')
jms_jar = os.path.abspath('./lib/javax.jms-api-2.0.1.jar')

# Start JVM if not already started
if not jpype.isJVMStarted():
    jpype.startJVM(classpath=[ibm_mq_jar, json_jar, jms_jar])

from com.ibm.mq import MQQueueManager
from com.ibm.mq.constants import CMQC
from com.ibm.mq import MQEnvironment

host, port = args.server.split(':')
port = int(port)

# Set up Java SSL properties
jpype.java.lang.System.setProperty("javax.net.ssl.keyStore", args.keystore)
jpype.java.lang.System.setProperty("javax.net.ssl.keyStorePassword", password)
jpype.java.lang.System.setProperty("javax.net.ssl.keyStoreType", "JKS")
jpype.java.lang.System.setProperty("javax.net.ssl.trustStore", truststore)
jpype.java.lang.System.setProperty("javax.net.ssl.trustStorePassword", password)
jpype.java.lang.System.setProperty("javax.net.ssl.trustStoreType", "JKS")

# Set up MQ environment
MQEnvironment.hostname = host
MQEnvironment.port = port
MQEnvironment.channel = args.channel
MQEnvironment.sslCipherSuite = args.ciphersuite

print(f"Connecting to {args.qm} at {args.server} on channel {args.channel} ...")

try:
    qmgr = MQQueueManager(args.qm)
    print(f"Connected to {args.qm}")
    open_opts = CMQC.MQOO_OUTPUT
    queue_obj = qmgr.accessQueue(args.queue, open_opts)
    print(f"Writing messages from {args.file} to queue: {args.queue}")
    MQMessage = jpype.JClass('com.ibm.mq.MQMessage')
    MQPutMessageOptions = jpype.JClass('com.ibm.mq.MQPutMessageOptions')
    with open(args.file, 'rb') as f:
        data = f.read()
        offset = 0
        msg_num = 0
        while offset < len(data):
            # For now, assume each message is the entire file (since MQbrowse.py writes concatenated raw messages)
            # If you want to support multiple messages, you need a delimiter or length prefix
            msg_bytes = data[offset:]
            mqmsg = MQMessage()
            mqmsg.writeBytes(msg_bytes)
            queue_obj.put(mqmsg, MQPutMessageOptions())
            msg_num += 1
            print(f"Wrote message {msg_num} ({len(msg_bytes)} bytes)")
            break  # Only one message unless a delimiter/length is implemented
    queue_obj.close()
    qmgr.disconnect()
    print(f"All messages written to {args.queue}")
except Exception as e:
    print(f"Error: {e}") 