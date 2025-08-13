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
parser = argparse.ArgumentParser(description='MQbrowse: IBM MQ queue browser and topic subscriber')
parser.add_argument('--keystore', help='Path to JKS, PFX, or PEM keystore file (optional - omit for TLS without client cert)')
parser.add_argument('--truststore', help='Path to JKS, PFX, or PEM truststore file (defaults to keystore if not provided)')
parser.add_argument('--keystoretype', default='JKS', choices=['JKS', 'PKCS12', 'PEM'], help='Keystore type: JKS, PKCS12, or PEM (default: JKS)')
parser.add_argument('--server', required=True, help='Server in host:port format')
parser.add_argument('--qm', required=True, help='Queue manager name')
parser.add_argument('--channel', required=True, help='Channel name')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--queue', help='Queue name')
group.add_argument('--topic', help='Topic string for publish/subscribe messaging')
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

# IBM MQ Reason Code lookup table with detailed explanations
MQ_REASON_CODES = {
    # Connection and communication errors
    2009: "MQRC_CONNECTION_BROKEN - The connection to the queue manager has been lost. This can occur due to network issues, queue manager restart, or timeout.",
    2059: "MQRC_Q_MGR_NOT_AVAILABLE - The queue manager is not available or not running. Check if the queue manager is started and accessible.",
    2538: "MQRC_HOST_NOT_AVAILABLE - Cannot connect to the specified host. Verify the hostname/IP address and network connectivity.",
    2540: "MQRC_CHANNEL_CONFIG_ERROR - Channel configuration is incorrect. Check channel definitions, cipher suites, and connection parameters.",
    2087: "MQRC_UNKNOWN_REMOTE_Q_MGR - The remote queue manager name is not recognized. Verify the queue manager name is correct.",
    
    # Authentication and authorization errors
    2035: "MQRC_NOT_AUTHORIZED - Access denied. You don't have permission to perform this operation. Check user permissions and queue/channel authorities.",
    2089: "MQRC_SECURITY_ERROR - A security-related error occurred. This could be authentication failure, certificate issues, or security policy violations.",
    
    # Queue manager errors
    2058: "MQRC_Q_MGR_NAME_ERROR - The queue manager name is invalid or incorrectly specified. Check the queue manager name spelling and case.",
    2071: "MQRC_Q_MGR_STOPPING - The queue manager is currently stopping. Wait for it to restart or connect to a different queue manager.",
    2072: "MQRC_Q_MGR_QUIESCING - The queue manager is quiescing (shutting down gracefully). New connections are not being accepted.",
    
    # Queue and object errors
    2085: "MQRC_UNKNOWN_OBJECT_NAME - The specified queue or object name doesn't exist. Verify the queue name is correct and the queue exists.",
    2082: "MQRC_UNKNOWN_ALIAS_BASE_Q - The base queue referenced by an alias queue is unknown. Check the alias queue definition and target queue.",
    2041: "MQRC_OBJECT_IN_USE - The object is currently being used by another process and cannot be modified or deleted.",
    2393: "MQRC_OBJECT_ALREADY_EXISTS - You attempted to create an MQ object but an object with the same name already exists in the queue manager.",
    2397: "MQRC_OBJECT_TYPE_ERROR - The object type is incorrect for the requested operation. For example, trying to browse a topic instead of a queue.",
    
    # Message operations
    2016: "MQRC_GET_INHIBITED - Get operations are disabled on this queue. The queue has been configured to prevent message retrieval.",
    2019: "MQRC_PUT_INHIBITED - Put operations are disabled on this queue. The queue has been configured to prevent new messages being added.",
    2033: "MQRC_NO_MSG_AVAILABLE - No messages are available on the queue. The queue is empty or no messages match your selection criteria.",
    2051: "MQRC_PUT_NOT_ALLOWED - Put operations are not allowed with the current queue open options. Reopen the queue with MQOO_OUTPUT.",
    2052: "MQRC_GET_NOT_ALLOWED - Get operations are not allowed with the current queue open options. Reopen the queue with MQOO_INPUT_* options.",
    2053: "MQRC_BROWSE_NOT_ALLOWED - Browse operations are not allowed with the current queue open options. Reopen the queue with MQOO_BROWSE.",
    2119: "MQRC_NOT_OPEN_FOR_BROWSE - The queue is not open for browsing. You need to open the queue with MQOO_BROWSE option first.",
    
    # Message size errors
    2030: "MQRC_MSG_TOO_BIG_FOR_Q - The message is too large for this queue. Check the queue's maximum message length setting.",
    2031: "MQRC_MSG_TOO_BIG_FOR_Q_MGR - The message exceeds the queue manager's maximum message length limit.",
    2020: "MQRC_MSG_TOO_BIG_FOR_CHANNEL - The message is too large to be transmitted over this channel. Check the channel's maximum message length.",
    
    # SSL/TLS errors
    2548: "MQRC_SSL_INITIALIZATION_ERROR - SSL/TLS initialization failed. Check certificate configuration, cipher suites, and SSL settings.",
    2551: "MQRC_SSL_CERTIFICATE_REVOKED - The SSL certificate has been revoked. Obtain a new, valid certificate.",
    2552: "MQRC_SSL_PEER_NAME_MISMATCH - The SSL certificate's distinguished name doesn't match the expected peer name. Check certificate CN/SAN fields.",
    2555: "MQRC_SSL_CERTIFICATE_REJECTED - The SSL certificate was rejected. This could be due to expiration, invalid CA, or other certificate validation issues.",
    
    # System and resource errors
    2069: "MQRC_STORAGE_NOT_AVAILABLE - Insufficient storage space available. The queue manager may be running low on disk space or memory.",
    2024: "MQRC_SYNCPOINT_LIMIT_REACHED - The limit for the number of uncommitted messages under syncpoint has been reached.",
    2195: "MQRC_UNEXPECTED_ERROR - An unexpected internal error occurred. Check queue manager logs for more details.",
    
    # Additional common error codes
    2001: "MQRC_ALIAS_BASE_Q_TYPE_ERROR - The base queue type is incorrect for an alias queue. Alias queues must point to local or remote queues.",
    2003: "MQRC_ALREADY_CONNECTED - Already connected to a queue manager. You cannot connect twice with the same connection handle.",
    2004: "MQRC_BUFFER_ERROR - A buffer provided to an MQ call is invalid. Check buffer pointers and memory allocation.",
    2005: "MQRC_BUFFER_LENGTH_ERROR - The buffer length is incorrect. The buffer may be too small for the operation or negative length specified.",
    2006: "MQRC_CHAR_ATTR_LENGTH_ERROR - A character attribute length is incorrect. Check string lengths in MQOD, MQMD, or other structures.",
    2007: "MQRC_CHAR_ATTRS_ERROR - Character attributes contain invalid data. Check for null characters or invalid string formats.",
    2008: "MQRC_CHAR_ATTRS_TOO_SHORT - Character attributes are shorter than required. Ensure strings are properly null-terminated.",
    2010: "MQRC_CONNECTION_QUIESCING - The connection is quiescing. The queue manager is preparing to shut down this connection.",
    2012: "MQRC_DATA_LENGTH_ERROR - The data length is invalid. This could be negative length or length exceeding maximum message size.",
    2017: "MQRC_ENVIRONMENT_ERROR - MQ environment setup error. Check MQ installation, libraries, and environment variables.",
    2018: "MQRC_EXPIRY_ERROR - Message expiry value is invalid. Expiry time must be positive or MQEI_UNLIMITED.",
    2022: "MQRC_FORMAT_ERROR - Message format is invalid. Check the format field in the message descriptor (MQMD).",
    2025: "MQRC_HANDLE_NOT_AVAILABLE - No more object handles are available. Close unused objects or increase handle limits.",
    2026: "MQRC_HANDLE_IN_USE - The object handle is already in use. You may be trying to reuse a handle that's still active.",
    2027: "MQRC_HCONN_ERROR - Connection handle is invalid. The handle may be corrupted, already disconnected, or never connected.",
    2028: "MQRC_HOBJ_ERROR - Object handle is invalid. The handle may be corrupted, already closed, or never opened.",
    2029: "MQRC_INHIBIT_VALUE_ERROR - Inhibit value is invalid. Check put/get inhibit settings in queue definitions.",
    2034: "MQRC_MD_ERROR - Message descriptor (MQMD) contains invalid data. Check all fields in the MQMD structure.",
    2036: "MQRC_NOT_OPEN_FOR_INPUT - The queue is not open for input operations. Reopen with MQOO_INPUT_SHARED or MQOO_INPUT_EXCLUSIVE.",
    2037: "MQRC_NOT_OPEN_FOR_INQUIRE - The object is not open for inquire operations. Reopen with MQOO_INQUIRE option.",
    2038: "MQRC_NOT_OPEN_FOR_OUTPUT - The queue is not open for output operations. Reopen with MQOO_OUTPUT option.",
    2039: "MQRC_NOT_OPEN_FOR_SET - The object is not open for set operations. Reopen with MQOO_SET option.",
    2040: "MQRC_OBJECT_CHANGED - The object has been changed by another process. Reopen the object to get the current definition.",
    2043: "MQRC_OPTION_NOT_VALID_FOR_TYPE - The specified option is not valid for this object type. Check open options against object capabilities.",
    2044: "MQRC_OPTIONS_ERROR - Invalid options specified. Check the options parameter for invalid or conflicting option combinations.",
    2045: "MQRC_PERSISTENCE_ERROR - Message persistence setting is invalid. Check if persistence is allowed for this queue and message type.",
    2046: "MQRC_PERSISTENT_NOT_ALLOWED - Persistent messages are not allowed. The queue or queue manager may not support persistent messages.",
    2047: "MQRC_PRIORITY_EXCEEDS_MAXIMUM - Message priority exceeds the maximum allowed value. Priority must be between 0 and 9.",
    2048: "MQRC_PRIORITY_ERROR - Message priority value is invalid. Priority must be a valid integer between 0 and 9.",
    2049: "MQRC_PUT_MSG_OPTS_ERROR - Put message options (MQPMO) contain invalid data. Check all fields in the MQPMO structure.",
    2050: "MQRC_Q_DELETED - The queue has been deleted. The queue was removed while you had it open.",
    2054: "MQRC_Q_FULL - The queue is full and cannot accept more messages. Remove some messages or increase the queue depth limit.",
    2055: "MQRC_Q_NOT_EMPTY - The queue is not empty when it needs to be. Some operations require an empty queue to proceed.",
    2056: "MQRC_Q_SPACE_NOT_AVAILABLE - Insufficient space available for the queue operation. The queue may have reached its size limits.",
    2057: "MQRC_Q_TYPE_ERROR - Invalid queue type for the requested operation. For example, you cannot put messages to a model queue.",
    2061: "MQRC_REPORT_OPTIONS_ERROR - Report options in the message descriptor are invalid. Check the Report field in MQMD.",
    2062: "MQRC_SECOND_MARK_NOT_ALLOWED - A second unit of work mark is not allowed. Complete or back out the current unit of work first.",
    2063: "MQRC_SECURITY_ERROR - A security error occurred. This could be authentication, authorization, or security policy violation.",
    2065: "MQRC_SELECTOR_COUNT_ERROR - The number of selectors is invalid. Check the selector count in MQGET operations.",
    2066: "MQRC_SELECTOR_LIMIT_EXCEEDED - Too many selectors specified. Reduce the number of message selectors in your request.",
    2067: "MQRC_SELECTOR_ERROR - Message selector contains invalid syntax. Check the selector string for proper SQL-like syntax.",
    2068: "MQRC_SELECTOR_NOT_FOR_TYPE - Selectors are not supported for this object type. Selectors typically work with topics, not queues.",
    2070: "MQRC_SOURCE_CCSID_ERROR - Source coded character set ID (CCSID) is invalid. Check the source CCSID value.",
    2073: "MQRC_TARGET_CCSID_ERROR - Target coded character set ID (CCSID) is invalid. Check the target CCSID value.",
    2074: "MQRC_TRUNCATED_MSG_ACCEPTED - The message was truncated but the operation completed. The buffer was too small for the full message.",
    2075: "MQRC_TRUNCATED_MSG_FAILED - The message was truncated and the operation failed. Provide a larger buffer for the message.",
    2076: "MQRC_UNKNOWN_OBJECT_TYPE - The object type is not recognized. Check that you're using a valid MQOT_* constant.",
    2077: "MQRC_UNKNOWN_REPORT_OPTION - An unknown report option was specified. Check the Report field values in the message descriptor.",
    2078: "MQRC_WAIT_INTERVAL_ERROR - Wait interval value is invalid. Wait intervals must be positive or MQWI_UNLIMITED.",
    2079: "MQRC_XMIT_Q_TYPE_ERROR - Transmission queue type is incorrect. Transmission queues must be local queues, not aliases or remote queues.",
    2080: "MQRC_XMIT_Q_USAGE_ERROR - Transmission queue usage is incorrect. The queue is not properly configured for transmission.",
    2081: "MQRC_NOT_OPEN_FOR_PASS_ALL - The queue is not open for pass-all operations. Some administrative operations require special open options.",
    2083: "MQRC_UNKNOWN_DEF_XMIT_Q - The default transmission queue is unknown. Check the queue manager's default transmission queue setting.",
    2084: "MQRC_DEF_XMIT_Q_TYPE_ERROR - Default transmission queue type is incorrect. The default transmission queue must be a local queue.",
    2086: "MQRC_DEF_XMIT_Q_USAGE_ERROR - Default transmission queue usage is incorrect. Check the queue definition and usage settings.",
    2088: "MQRC_NAME_IN_USE - The name is already in use by another object. Choose a different name for the new object.",
    2090: "MQRC_CONNECTION_QUIESCING - The connection is in quiescing state. The queue manager is preparing to close this connection.",
    2091: "MQRC_CONNECTION_SHUTTING_DOWN - The connection is shutting down. The connection will be closed soon.",
    2092: "MQRC_INVALID_LOG_TYPE - The log type specified is invalid. Check queue manager logging configuration.",
    2093: "MQRC_INVALID_MEDIA_RECOVERY - Media recovery operation is invalid for this queue manager configuration.",
    2094: "MQRC_INVALID_RESTART_TYPE - The restart type specified is invalid. Check queue manager restart options."
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

# Determine if we're working with queue or topic
is_topic_mode = args.topic is not None
target_name = args.topic if is_topic_mode else args.queue
operation_type = "topic" if is_topic_mode else "queue"

print(f"Connecting to {args.qm} at {args.server} on channel {args.channel} ...")
print(f"Mode: {'Topic subscription' if is_topic_mode else 'Queue browsing'}")

# Prepare log directory
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
session_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
msg_counter = 0
print(f"Logging each raw message to its own file in {log_dir}/")

try:
    qmgr = MQQueueManager(args.qm)
    print(f"Connected to {args.qm}")
    
    MQMessage = jpype.JClass('com.ibm.mq.MQMessage')
    MQGetMessageOptions = jpype.JClass('com.ibm.mq.MQGetMessageOptions')
    
    if is_topic_mode:
        # Topic subscription mode
        MQTopic = jpype.JClass('com.ibm.mq.MQTopic')
        MQSubscription = jpype.JClass('com.ibm.mq.MQSubscription')
        
        # Create topic object for subscription
        topic_obj = qmgr.accessTopic(args.topic, "", CMQC.MQTOPIC_OPEN_AS_SUBSCRIPTION, CMQC.MQOO_INPUT_SHARED)
        print(f"Subscribed to topic: {args.topic} (Ctrl+C to exit)")
        
        # Set up message options for topic
        gmo = MQGetMessageOptions()
        gmo.options = CMQC.MQGMO_WAIT | CMQC.MQGMO_NO_SYNCPOINT
        gmo.waitInterval = 5000  # 5 second wait
        
        source_obj = topic_obj
        
    else:
        # Queue browsing mode
        open_opts = CMQC.MQOO_BROWSE | CMQC.MQOO_INPUT_SHARED
        queue_obj = qmgr.accessQueue(args.queue, open_opts)
        print(f"Browsing queue: {args.queue} (Ctrl+C to exit)")
        
        # Set up message options for queue browsing
        gmo = MQGetMessageOptions()
        gmo.options = CMQC.MQGMO_BROWSE_FIRST | CMQC.MQGMO_NO_WAIT
        
        source_obj = queue_obj
    
    # Message reading loop
    while True:
        try:
            mqmsg = MQMessage()
            source_obj.get(mqmsg, gmo)
            msg_bytes = mqmsg.readBytes(mqmsg.getDataLength())
            msg_counter += 1
            
            # Create filename based on mode
            safe_name = target_name.replace('/', '_').replace('\\', '_')
            msg_filename = os.path.join(
                log_dir,
                f"{safe_name}_{session_time}_{msg_counter:04d}.log"
            )
            
            with open(msg_filename, 'wb') as log_file:
                log_file.write(msg_bytes)
            print(f"Message {msg_counter}: {msg_filename} ({len(msg_bytes)} bytes)")
            
            # For queue browsing, switch to BROWSE_NEXT after first message
            if not is_topic_mode and gmo.options & CMQC.MQGMO_BROWSE_FIRST:
                gmo.options = CMQC.MQGMO_BROWSE_NEXT | CMQC.MQGMO_NO_WAIT
                
        except Exception as e:
            if is_topic_mode:
                # For topics, continue waiting for new messages
                continue
            else:
                # For queues, no more messages, wait a bit then try again
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
    else:
        print(f"Could not extract reason code from exception: {str(e)}")
finally:
    try:
        # Close the appropriate object
        if 'source_obj' in locals():
            source_obj.close()
        if 'qmgr' in locals():
            qmgr.disconnect()
            print(f"Disconnected from {args.qm}")
    except:
        pass 