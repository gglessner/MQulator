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
parser.add_argument('--keystore', help='Path to JKS, PFX, or PEM keystore file (optional - omit for TLS without client cert)')
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

# Handle keystore and truststore configuration
if args.keystore:
    # Use keystore as truststore if not provided
    truststore = args.truststore if args.truststore else args.keystore
    
    # Only prompt for password if not using PEM
    if args.keystoretype == 'PEM':
        password = None
        print("Using PEM keystore (no password required)")
    else:
        password = getpass.getpass(f'Enter {args.keystoretype} password (used for both keystore and truststore): ')
else:
    # No keystore provided - TLS without client certificate
    print("No keystore provided - using TLS without client certificate authentication")
    truststore = None
    password = None

# JAR paths (assume same as MQulator)
ibm_mq_jar = os.path.abspath('./lib/com.ibm.mq.allclient-9.4.1.0.jar')
json_jar = os.path.abspath('./lib/json-20240303.jar')
jms_jar = os.path.abspath('./lib/javax.jms-api-2.0.1.jar')

# Start JVM if not already started
if not jpype.isJVMStarted():
    # Add additional JVM args for certificate bypass if needed
    jvm_args = []
    if len([arg for arg in sys.argv if '--disable-cert-verification' in arg]) > 0:
        jvm_args.extend([
            '-Dcom.ibm.ssl.enableSignerExchangePrompt=false',
            '-Dcom.ibm.ssl.performURLHostnameVerification=false',
            '-Dtrust_all_cert=true'
        ])
    jpype.startJVM(classpath=[ibm_mq_jar, json_jar, jms_jar], *jvm_args)

from com.ibm.mq import MQQueueManager
from com.ibm.mq.constants import CMQC
from com.ibm.mq import MQEnvironment

# IBM MQ Reason Code lookup table
MQ_REASON_CODES = {
    # Connection and communication errors
    2009: "MQRC_CONNECTION_BROKEN",
    2059: "MQRC_Q_MGR_NOT_AVAILABLE",
    2538: "MQRC_HOST_NOT_AVAILABLE",
    2540: "MQRC_CHANNEL_CONFIG_ERROR",
    2087: "MQRC_UNKNOWN_REMOTE_Q_MGR",
    
    # Authentication and authorization errors
    2035: "MQRC_NOT_AUTHORIZED",
    2089: "MQRC_SECURITY_ERROR",
    
    # Queue manager errors
    2058: "MQRC_Q_MGR_NAME_ERROR",
    2071: "MQRC_Q_MGR_STOPPING",
    2072: "MQRC_Q_MGR_QUIESCING",
    
    # Queue and object errors
    2085: "MQRC_UNKNOWN_OBJECT_NAME",
    2082: "MQRC_UNKNOWN_ALIAS_BASE_Q",
    2041: "MQRC_OBJECT_IN_USE",
    2393: "MQRC_OBJECT_ALREADY_EXISTS",
    2397: "MQRC_OBJECT_TYPE_ERROR",
    
    # Message operations
    2016: "MQRC_GET_INHIBITED",
    2019: "MQRC_PUT_INHIBITED",
    2033: "MQRC_NO_MSG_AVAILABLE",
    2051: "MQRC_PUT_NOT_ALLOWED",
    2052: "MQRC_GET_NOT_ALLOWED",
    2053: "MQRC_BROWSE_NOT_ALLOWED",
    2119: "MQRC_NOT_OPEN_FOR_BROWSE",
    
    # Message size errors
    2030: "MQRC_MSG_TOO_BIG_FOR_Q",
    2031: "MQRC_MSG_TOO_BIG_FOR_Q_MGR",
    2020: "MQRC_MSG_TOO_BIG_FOR_CHANNEL",
    
    # SSL/TLS errors
    2548: "MQRC_SSL_INITIALIZATION_ERROR",
    2551: "MQRC_SSL_CERTIFICATE_REVOKED",
    2552: "MQRC_SSL_PEER_NAME_MISMATCH",
    2555: "MQRC_SSL_CERTIFICATE_REJECTED",
    
    # System and resource errors
    2069: "MQRC_STORAGE_NOT_AVAILABLE",
    2024: "MQRC_SYNCPOINT_LIMIT_REACHED",
    2195: "MQRC_UNEXPECTED_ERROR",
    
    # Additional common error codes
    2001: "MQRC_ALIAS_BASE_Q_TYPE_ERROR",
    2003: "MQRC_ALREADY_CONNECTED",
    2004: "MQRC_BUFFER_ERROR",
    2005: "MQRC_BUFFER_LENGTH_ERROR",
    2006: "MQRC_CHAR_ATTR_LENGTH_ERROR",
    2007: "MQRC_CHAR_ATTRS_ERROR",
    2008: "MQRC_CHAR_ATTRS_TOO_SHORT",
    2010: "MQRC_CONNECTION_QUIESCING",
    2012: "MQRC_DATA_LENGTH_ERROR",
    2017: "MQRC_ENVIRONMENT_ERROR",
    2018: "MQRC_EXPIRY_ERROR",
    2022: "MQRC_FORMAT_ERROR",
    2025: "MQRC_HANDLE_NOT_AVAILABLE",
    2026: "MQRC_HANDLE_IN_USE",
    2027: "MQRC_HCONN_ERROR",
    2028: "MQRC_HOBJ_ERROR",
    2029: "MQRC_INHIBIT_VALUE_ERROR",
    2034: "MQRC_MD_ERROR",
    2036: "MQRC_NOT_OPEN_FOR_INPUT",
    2037: "MQRC_NOT_OPEN_FOR_INQUIRE",
    2038: "MQRC_NOT_OPEN_FOR_OUTPUT",
    2039: "MQRC_NOT_OPEN_FOR_SET",
    2040: "MQRC_OBJECT_CHANGED",
    2043: "MQRC_OPTION_NOT_VALID_FOR_TYPE",
    2044: "MQRC_OPTIONS_ERROR",
    2045: "MQRC_PERSISTENCE_ERROR",
    2046: "MQRC_PERSISTENT_NOT_ALLOWED",
    2047: "MQRC_PRIORITY_EXCEEDS_MAXIMUM",
    2048: "MQRC_PRIORITY_ERROR",
    2049: "MQRC_PUT_MSG_OPTS_ERROR",
    2050: "MQRC_Q_DELETED",
    2054: "MQRC_Q_FULL",
    2055: "MQRC_Q_NOT_EMPTY",
    2056: "MQRC_Q_SPACE_NOT_AVAILABLE",
    2057: "MQRC_Q_TYPE_ERROR",
    2061: "MQRC_REPORT_OPTIONS_ERROR",
    2062: "MQRC_SECOND_MARK_NOT_ALLOWED",
    2063: "MQRC_SECURITY_ERROR",
    2065: "MQRC_SELECTOR_COUNT_ERROR",
    2066: "MQRC_SELECTOR_LIMIT_EXCEEDED",
    2067: "MQRC_SELECTOR_ERROR",
    2068: "MQRC_SELECTOR_NOT_FOR_TYPE",
    2070: "MQRC_SOURCE_CCSID_ERROR",
    2073: "MQRC_TARGET_CCSID_ERROR",
    2074: "MQRC_TRUNCATED_MSG_ACCEPTED",
    2075: "MQRC_TRUNCATED_MSG_FAILED",
    2076: "MQRC_UNKNOWN_OBJECT_TYPE",
    2077: "MQRC_UNKNOWN_REPORT_OPTION",
    2078: "MQRC_WAIT_INTERVAL_ERROR",
    2079: "MQRC_XMIT_Q_TYPE_ERROR",
    2080: "MQRC_XMIT_Q_USAGE_ERROR",
    2081: "MQRC_NOT_OPEN_FOR_PASS_ALL",
    2083: "MQRC_UNKNOWN_DEF_XMIT_Q",
    2084: "MQRC_DEF_XMIT_Q_TYPE_ERROR",
    2086: "MQRC_DEF_XMIT_Q_USAGE_ERROR",
    2088: "MQRC_NAME_IN_USE",
    2090: "MQRC_CONNECTION_QUIESCING",
    2091: "MQRC_CONNECTION_SHUTTING_DOWN",
    2092: "MQRC_INVALID_LOG_TYPE",
    2093: "MQRC_INVALID_MEDIA_RECOVERY",
    2094: "MQRC_INVALID_RESTART_TYPE"
}

host, port = args.server.split(':')
port = int(port)

# Set up Java SSL properties
if args.keystore:
    # Client certificate authentication
    jpype.java.lang.System.setProperty("javax.net.ssl.keyStore", args.keystore)
    jpype.java.lang.System.setProperty("javax.net.ssl.keyStoreType", args.keystoretype)
    jpype.java.lang.System.setProperty("javax.net.ssl.trustStore", truststore)
    jpype.java.lang.System.setProperty("javax.net.ssl.trustStoreType", args.keystoretype)
    
    # Only set passwords for non-PEM keystores
    if args.keystoretype != "PEM":
        jpype.java.lang.System.setProperty("javax.net.ssl.keyStorePassword", password)
        jpype.java.lang.System.setProperty("javax.net.ssl.trustStorePassword", password)
else:
    # TLS without client certificate - use default trust store
    print("Configuring TLS without client certificate...")
    # Clear any keystore properties to ensure no client cert is used
    jpype.java.lang.System.clearProperty("javax.net.ssl.keyStore")
    jpype.java.lang.System.clearProperty("javax.net.ssl.keyStorePassword")
    jpype.java.lang.System.clearProperty("javax.net.ssl.keyStoreType")
    
    # Use system default trust store unless disabled
    if not args.disable_cert_verification:
        # Let Java use its default trust store (cacerts)
        print("Using system default trust store for server certificate validation")

# Enable TLS debugging if requested
if args.debug_tls:
    print("Enabling TLS handshake debugging...")
    jpype.java.lang.System.setProperty("javax.net.debug", "ssl,handshake")
    jpype.java.lang.System.setProperty("com.ibm.ssl.debug", "true")

# Disable certificate verification if requested
if args.disable_cert_verification:
    print("WARNING: Disabling server certificate verification - use with caution!")
    
    # Create a custom trust manager that accepts all certificates
    try:
        # Import required Java classes for custom trust manager
        TrustManager = jpype.JClass('javax.net.ssl.TrustManager')
        X509TrustManager = jpype.JClass('javax.net.ssl.X509TrustManager')
        SSLContext = jpype.JClass('javax.net.ssl.SSLContext')
        
        # Define a custom trust manager that accepts all certificates
        @jpype.JImplements(X509TrustManager)
        class AcceptAllTrustManager:
            @jpype.JOverride
            def checkClientTrusted(self, chain, authType):
                pass
            
            @jpype.JOverride
            def checkServerTrusted(self, chain, authType):
                pass
            
            @jpype.JOverride
            def getAcceptedIssuers(self):
                return jpype.JArray(jpype.JClass('java.security.cert.X509Certificate'))(0)
        
        # Create and install the custom trust manager
        trust_manager = AcceptAllTrustManager()
        trust_managers = jpype.JArray(TrustManager)([trust_manager])
        
        ssl_context = SSLContext.getInstance("TLS")
        ssl_context.init(None, trust_managers, None)
        SSLContext.setDefault(ssl_context)
        
        # Make MQ actually use it:
        from com.ibm.mq import MQEnvironment
        MQEnvironment.sslSocketFactory = ssl_context.getSocketFactory()

        print("Custom trust-all manager installed successfully")
        
        # Additional IBM MQ specific certificate bypass properties
        jpype.java.lang.System.setProperty("com.ibm.ssl.enableSignerExchangePrompt", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.performURLHostnameVerification", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.checkCertificateRevocation", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.trustDefaultCerts", "true")
        jpype.java.lang.System.setProperty("com.ibm.ssl.enableCertificateValidation", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.skipCertificateValidation", "true")
        jpype.java.lang.System.setProperty("com.ibm.mq.ssl.validateCertificate", "false")
        
        # Disable PKIX path validation
        jpype.java.lang.System.setProperty("com.sun.net.ssl.checkRevocation", "false")
        jpype.java.lang.System.setProperty("com.sun.security.enableCRLDP", "false")
        jpype.java.lang.System.setProperty("ocsp.enable", "false")
        
    except Exception as e:
        print(f"Failed to create custom trust manager: {e}")
        # Fallback to property-based approach with all bypass properties
        jpype.java.lang.System.setProperty("com.ibm.ssl.enableSignerExchangePrompt", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.performURLHostnameVerification", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.checkCertificateRevocation", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.trustDefaultCerts", "true")
        jpype.java.lang.System.setProperty("com.ibm.ssl.enableCertificateValidation", "false")
        jpype.java.lang.System.setProperty("com.ibm.ssl.skipCertificateValidation", "true")
        jpype.java.lang.System.setProperty("com.ibm.mq.ssl.validateCertificate", "false")
        jpype.java.lang.System.setProperty("com.sun.net.ssl.checkRevocation", "false")
        jpype.java.lang.System.setProperty("com.sun.security.enableCRLDP", "false")
        jpype.java.lang.System.setProperty("ocsp.enable", "false")
        
else:
    # Normal operation - ensure truststore is properly set
    if args.keystore and args.keystoretype != "PEM":
        jpype.java.lang.System.setProperty("javax.net.ssl.trustStore", truststore)
        jpype.java.lang.System.setProperty("javax.net.ssl.trustStoreType", args.keystoretype)

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
    # Try to extract and decode MQ reason code
    reason_code = None
    # MQException from Java side may have reasonCode attribute
    if hasattr(e, 'reasonCode'):
        reason_code = e.reasonCode
    else:
        # Try to parse from string (e.g., 'MQJE001: Completion Code 2, Reason 2033')
        import re
        m = re.search(r'Reason (\d+)', str(e))
        if m:
            reason_code = int(m.group(1))
    if reason_code is not None:
        reason_text = MQ_REASON_CODES.get(reason_code, 'Unknown reason code')
        print(f"IBM MQ Reason Code {reason_code}: {reason_text}")
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