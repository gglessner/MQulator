#!/usr/bin/env python3
# MQbrowse - Simple IBM MQ queue browser
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
import time
import getpass
import datetime

# Argument parsing
parser = argparse.ArgumentParser(description='MQbrowse: Simple IBM MQ queue browser')
parser.add_argument('--keystore', required=True, help='Path to JKS keystore file')
parser.add_argument('--truststore', help='Path to JKS truststore file (defaults to keystore if not provided)')
parser.add_argument('--server', required=True, help='Server in host:port format')
parser.add_argument('--qm', required=True, help='Queue manager name')
parser.add_argument('--channel', required=True, help='Channel name')
parser.add_argument('--queue', required=True, help='Queue name')
parser.add_argument('--ciphersuite', default='TLS_RSA_WITH_AES_256_CBC_SHA256', help='TLS cipher suite (default: TLS_RSA_WITH_AES_256_CBC_SHA256)')
args = parser.parse_args()

# Use keystore as truststore if not provided
truststore = args.truststore if args.truststore else args.keystore

password = getpass.getpass('Enter JKS password (used for both keystore and truststore): ')

# JAR paths (assume same as MQulator)
ibm_mq_jar = os.path.abspath('./lib/com.ibm.mq.allclient-9.4.1.0.jr')
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

# Prepare log file
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
log_filename = os.path.join(
    log_dir,
    f"{args.queue}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)
log_file = open(log_filename, 'ab')  # append in binary mode
print(f"Logging raw messages to {log_filename}")

try:
    qmgr = MQQueueManager(args.qm)
    print(f"Connected to {args.qm}")
    open_opts = CMQC.MQOO_BROWSE | CMQC.MQOO_INPUT_SHARED
    queue_obj = qmgr.accessQueue(args.queue, open_opts)
    print(f"Browsing queue: {args.queue} (Ctrl+C to exit)")
    MQMessage = jpype.JClass('com.ibm.mq.MQMessage')
    MQGetMessageOptions = jpype.JClass('com.ibm.mq.MQGetMessageOptions')
    gmo = MQGetMessageOptions()
    gmo.options = CMQC.MQGMO_BROWSE_FIRST | CMQC.MQGMO_NO_WAIT
    while True:
        try:
            mqmsg = MQMessage()
            queue_obj.get(mqmsg, gmo)
            msg_bytes = mqmsg.readBytes(mqmsg.getDataLength())
            log_file.write(msg_bytes)
            log_file.flush()
            print(f"Message: {msg_bytes}")
            # After first message, switch to BROWSE_NEXT
            gmo.options = CMQC.MQGMO_BROWSE_NEXT | CMQC.MQGMO_NO_WAIT
        except Exception as e:
            # No more messages, wait a bit then try again
            time.sleep(1)
except KeyboardInterrupt:
    print("\nExiting on user request.")
except Exception as e:
    print(f"Error: {e}")
finally:
    try:
        log_file.close()
        queue_obj.close()
        qmgr.disconnect()
    except:
        pass 