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
parser.add_argument('--keystore', required=True, help='Path to JKS, PFX, or PEM keystore file')
parser.add_argument('--truststore', help='Path to JKS, PFX, or PEM truststore file (defaults to keystore if not provided)')
parser.add_argument('--keystoretype', default='JKS', choices=['JKS', 'PKCS12', 'PEM'], help='Keystore type: JKS, PKCS12, or PEM (default: JKS)')
parser.add_argument('--server', required=True, help='Server in host:port format')
parser.add_argument('--qm', required=True, help='Queue manager name')
parser.add_argument('--channel', required=True, help='Channel name')
parser.add_argument('--queue', required=True, help='Queue name')
parser.add_argument('--ciphersuite', default='TLS_RSA_WITH_AES_256_CBC_SHA256', help='TLS cipher suite (default: TLS_RSA_WITH_AES_256_CBC_SHA256)')
parser.add_argument('--debug-tls', action='store_true', help='Enable TLS handshake debugging (verbose output)')
parser.add_argument('--disable-cert-verification', action='store_true', help='Disable server certificate verification (use with caution)')
args = parser.parse_args()

# Use keystore as truststore if not provided
truststore = args.truststore if args.truststore else args.keystore

# Only prompt for password if not using PEM
if args.keystoretype == 'PEM':
    password = None
    print("Using PEM keystore (no password required)")
else:
    password = getpass.getpass(f'Enter {args.keystoretype} password (used for both keystore and truststore): ')

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
jpype.java.lang.System.setProperty("javax.net.ssl.keyStoreType", args.keystoretype)
jpype.java.lang.System.setProperty("javax.net.ssl.trustStore", truststore)
jpype.java.lang.System.setProperty("javax.net.ssl.trustStoreType", args.keystoretype)

# Only set passwords for non-PEM keystores
if args.keystoretype != "PEM":
    jpype.java.lang.System.setProperty("javax.net.ssl.keyStorePassword", password)
    jpype.java.lang.System.setProperty("javax.net.ssl.trustStorePassword", password)

# Enable TLS debugging if requested
if args.debug_tls:
    print("Enabling TLS handshake debugging...")
    jpype.java.lang.System.setProperty("javax.net.debug", "ssl,handshake")
    jpype.java.lang.System.setProperty("com.ibm.ssl.debug", "true")

# Disable certificate verification if requested
if args.disable_cert_verification:
    print("WARNING: Disabling server certificate verification - use with caution!")
    jpype.java.lang.System.setProperty("com.ibm.ssl.trustManager", "com.ibm.ssl.TrustManagerExtended")
    jpype.java.lang.System.setProperty("com.ibm.ssl.trustStoreType", "NONE")
    jpype.java.lang.System.setProperty("javax.net.ssl.trustStore", "")
    jpype.java.lang.System.setProperty("javax.net.ssl.trustStoreType", "NONE")

# Set up MQ environment
MQEnvironment.hostname = host
MQEnvironment.port = port
MQEnvironment.channel = args.channel
MQEnvironment.sslCipherSuite = args.ciphersuite

print(f"Connecting to {args.qm} at {args.server} on channel {args.channel} ...")

# Prepare log directory
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
session_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
msg_counter = 0
print(f"Logging each raw message to its own file in {log_dir}/")

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
            msg_counter += 1
            msg_filename = os.path.join(
                log_dir,
                f"{args.queue}_{session_time}_{msg_counter:04d}.log"
            )
            with open(msg_filename, 'wb') as log_file:
                log_file.write(msg_bytes)
            print(f"Message {msg_counter}: {msg_filename} ({len(msg_bytes)} bytes)")
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
        # The original code had log_file.close() here, but log_file is not defined in this scope.
        # Assuming the intent was to close the last opened log file if msg_counter > 0.
        # However, the original code had log_file.close() which was not defined.
        # I will remove the line as it's not directly related to the new_code and would cause an error.
        # If the user wants to close the last file, they should manage it.
        # queue_obj.close()
        qmgr.disconnect()
    except:
        pass 