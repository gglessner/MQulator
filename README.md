# MQulator

MQulator is a Python tool for browsing messages from IBM MQ queues using the IBM MQ Java client via JPype. It iterates through all combinations of servers, queue managers, channels, queues, and TLS certificates, connecting to each and displaying any messages found.

**In the spirit of Joe Grand's [JTAGulator](https://www.grandideastudio.com/jtagulator/), which tries all wiring combinations to identify JTAG, TTL serial, I2C, or SPI ports on hardware, MQulator is designed for security testers who may not be completely sure which IBM MQ settings belong together. It automates the process of trying all possible combinations to help identify valid connection parameters.**

## Features
- Connects to IBM MQ using Java client libraries
- Supports TLS with JKS certificates
- Iterates all combinations of connection parameters
- Prints detailed status and browsed messages

## Requirements
- Python 3.7+
- Java (JRE/JDK) installed and accessible in your PATH
- IBM MQ Java client JAR: `mq.allclient-9.4.1.0.jar`
- JSON JAR: `json-20240303.jar`
- JMS API JAR: `javax.jms-api-2.0.1.jar`
- Python packages: see `requirements.txt`

## Where to get the .jar files
- **IBM MQ allclient JAR**: Download from IBM's official site (requires IBM ID):
  - [IBM MQ Downloads](https://www.ibm.com/products/mq/downloads)
  - Look for "IBM MQ classes for Java and JMS" or "Client" package, which contains `mq.allclient-<version>.jar`.
- **JSON JAR**: Download from Maven Central:
  - [https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar](https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar)
- **JMS API JAR**: Download from Maven Central:
  - [https://repo1.maven.org/maven2/javax/jms/javax.jms-api/2.0.1/javax.jms-api-2.0.1.jar](https://repo1.maven.org/maven2/javax/jms/javax.jms-api/2.0.1/javax.jms-api-2.0.1.jar)

## Certificate Support
All tools support JKS, PFX (PKCS12), and PEM certificate formats:
- **MQulator**: Automatically detects keystore type based on file extension (.jks, .pfx, .p12, .pem)
- **MQbrowse/MQwrite**: Use `--keystoretype` argument to specify JKS, PKCS12, or PEM (defaults to JKS)
- **PEM files**: No password required (password prompts are skipped for PEM keystores)

Place all three JARs in the `./lib/` directory as follows:
```
./lib/com.ibm.mq.allclient-9.4.1.0.jar   # (rename as needed to match your version, must be .jar)
./lib/json-20240303.jar
./lib/javax.jms-api-2.0.1.jar
```

## Installation
1. Install Python dependencies:
   ```sh
   pip install -r requirements.txt
   ```
2. Ensure Java is installed and available in your PATH.
3. Download the required JAR files and place them in the `lib` directory as described above.

## Usage
Prepare the following input files (one entry per line):
- `server.txt`: `hostname:port`
- `qm.txt`: Queue Manager names
- `channel.txt`: Channel names
- `queue.txt`: Queue names
- `certs.txt`: `password|filename` (JKS file path)

Example command:
```sh
python MQulator.py --servers server.txt --qms qm.txt --channels channel.txt --queues queue.txt --certs certs.txt
```

Optional:
- `--cipher <CIPHER_SUITE>`: Override the default TLS cipher suite.
- `--debug-tls`: Enable TLS handshake debugging (verbose output for troubleshooting SSL/TLS issues).
- `--disable-cert-verification`: Disable server certificate verification (use with caution for testing).

## Example Input File Formats
- **server.txt**
  ```
  mqhost1.example.com:1414
  mqhost2.example.com:1414
  ```
- **qm.txt**
  ```
  QM1
  QM2
  ```
- **channel.txt**
  ```
  CHANNEL1
  CHANNEL2
  ```
- **queue.txt**
  ```
  QUEUE1
  QUEUE2
  ```
- **certs.txt**
  ```
  mypassword|./mycert.jks
  anotherpass|./anothercert.jks
  pfxpassword|./mycert.pfx
  p12password|./mycert.p12
  |./mycert.pem
  ```
  Note: For PEM files, leave the password field empty (just use `|./file.pem`)

## Error Handling and Reason Code Lookup

When an IBM MQ error occurs, all tools will attempt to extract the MQ reason code from the exception and print a human-readable explanation. The tools include **74 common IBM MQ reason codes** organized by category:

- **Connection and communication errors** (e.g., 2009 = MQRC_CONNECTION_BROKEN, 2538 = MQRC_HOST_NOT_AVAILABLE)
- **Authentication and authorization errors** (e.g., 2035 = MQRC_NOT_AUTHORIZED, 2089 = MQRC_SECURITY_ERROR)
- **Queue manager errors** (e.g., 2058 = MQRC_Q_MGR_NAME_ERROR, 2071 = MQRC_Q_MGR_STOPPING)
- **Queue and object errors** (e.g., 2085 = MQRC_UNKNOWN_OBJECT_NAME, 2041 = MQRC_OBJECT_IN_USE)
- **Message operations** (e.g., 2033 = MQRC_NO_MSG_AVAILABLE, 2016 = MQRC_GET_INHIBITED)
- **SSL/TLS errors** (e.g., 2548 = MQRC_SSL_INITIALIZATION_ERROR, 2552 = MQRC_SSL_PEER_NAME_MISMATCH)
- **System and resource errors** (e.g., 2069 = MQRC_STORAGE_NOT_AVAILABLE, 2195 = MQRC_UNEXPECTED_ERROR)

**Comprehensive Error Explanations:**
- **All tools** (MQulator.py, MQbrowse.py, and MQwrite.py): Provide comprehensive explanations with detailed troubleshooting guidance for each reason code

The reason code lookup table (`MQ_REASON_CODES` dictionary) is easily extensible. If you encounter a code not listed, you can add it to the table for more descriptive error messages.

## Object Type Verification

Both MQbrowse.py and MQwrite.py include automatic object type verification to help prevent errors caused by object type mismatches. Before attempting to access any queue or topic, the tools will:

1. **Connect to the queue manager**
2. **Check the actual object type** using IBM MQ inquire operations
3. **Display the verification results** with clear success or mismatch messages
4. **Provide guidance** when mismatches are detected

### Example Output

**When object type matches expectations:**
```
Connected to QMGR1
Checking object type for 'TEST.QUEUE' (expected: queue)...
✓ Object type confirmed: LOCAL QUEUE

Mode: Queue browsing
```

**When there's a type mismatch:**
```
Connected to QMGR1
Checking object type for 'TEST.QUEUE' (expected: topic)...
⚠ Object type mismatch!
  Expected: TOPIC
  Actual:   LOCAL QUEUE
  → Try using --queue instead of --topic

Mode: Topic subscription
```

**For topics that don't exist yet (valid for pub/sub):**
```
Connected to QMGR1
Checking object type for '/test/topic' (expected: topic)...
✓ Object type confirmed: TOPIC (will be created) - Topic will be created if it doesn't exist

Mode: Topic subscription
```

### Supported Object Types

The verification can detect and report:
- **LOCAL QUEUE**: Standard local queues
- **REMOTE QUEUE**: Queues on remote queue managers
- **ALIAS QUEUE**: Queue aliases
- **MODEL QUEUE**: Template queues for dynamic queue creation
- **TOPIC**: Publish/subscribe topics (existing or to be created)

This feature helps prevent common errors such as:
- Using `--queue` when the object is actually a topic
- Using `--topic` when the object is actually a queue
- IBM MQ reason code 2397 (object type error) caused by incorrect object type assumptions

## Additional Tools

### MQbrowse.py
A versatile tool that can both browse messages from IBM MQ queues and subscribe to IBM MQ topics for publish/subscribe messaging. It connects to the specified queue or topic and writes each raw message to its own timestamped file in the `logs` directory. Each file contains the raw, unaltered message bytes (suitable for re-injection).

**Queue Browsing Mode:**
```
# JKS keystore (default)
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1

# PFX keystore
python MQbrowse.py --keystore mycert.pfx --keystoretype PKCS12 --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1

# PEM keystore
python MQbrowse.py --keystore mycert.pem --keystoretype PEM --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1

# TLS without client certificate
python MQbrowse.py --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1
```

**Topic Subscription Mode:**
```
# Subscribe to a specific topic
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --topic /Sports/Football/Scores

# Subscribe with wildcards (+ for single level, # for multiple levels)
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --topic /Sports/+/Scores
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --topic /Sports/#

# Topic subscription without client certificate
python MQbrowse.py --server host:port --qm QM1 --channel CHANNEL1 --topic /News/Technology
```

**Additional Options:**
```
# Disable certificate verification (for testing with self-signed certs)
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --disable-cert-verification
```

**Key Features:**
- **Queue Mode**: Browses existing messages in a queue, then continues monitoring for new messages
- **Topic Mode**: Creates a subscription and waits for new messages published to the topic
- **Object Type Verification**: Automatically checks and displays the actual object type before attempting access to help prevent type mismatch errors
- Use `--truststore` if you want a different truststore; otherwise, the keystore is used for both.
- Use `--keystoretype PKCS12` for PFX/P12 files, `PEM` for PEM files, or `JKS` for JKS files (default).
- Use `--ciphersuite` to override the default TLS cipher suite.
- Use `--debug-tls` to enable verbose TLS handshake debugging for troubleshooting connection issues.
- Use `--disable-cert-verification` to bypass server certificate validation (useful for testing with self-signed certs).
- The tool will prompt for the keystore password (except for PEM files, which don't require passwords).
- The `--keystore` argument is optional - omit it for TLS without client certificate authentication.
- Each message is logged to its own file: `logs/TARGET_NAME_YYYYMMDD_HHMMSS_NNNN.log` (queue names or topic strings with special characters converted to underscores).

### MQwrite.py
A companion tool that can write raw messages (as logged by MQbrowse.py) to IBM MQ queues or publish them to topics. It reads a log file from the `logs` directory and writes its contents as a message to the specified queue or publishes it to a topic. You can use it to replay individual message files captured by MQbrowse.py.

**Queue Writing Mode:**
```
# JKS keystore (default)
python MQwrite.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --file logs/QUEUE1_YYYYMMDD_HHMMSS_NNNN.log

# PFX keystore
python MQwrite.py --keystore mycert.pfx --keystoretype PKCS12 --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --file logs/QUEUE1_YYYYMMDD_HHMMSS_NNNN.log

# PEM keystore
python MQwrite.py --keystore mycert.pem --keystoretype PEM --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --file logs/QUEUE1_YYYYMMDD_HHMMSS_NNNN.log
```

**Topic Publishing Mode:**
```
# Publish to a specific topic
python MQwrite.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --topic /Sports/Football/Scores --file logs/message.log

# Publish to different topic hierarchies
python MQwrite.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --topic /News/Technology --file logs/tech_news.log
python MQwrite.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --topic /Finance/StockPrices --file logs/stock_data.log
```

**Additional Options:**
```
# Disable certificate verification (for testing with self-signed certs)
python MQwrite.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --file logs/message.log --disable-cert-verification
```

**Key Features:**
- **Queue Mode**: Writes messages directly to a specific queue
- **Topic Mode**: Publishes messages to a topic for distribution to subscribers
- **Object Type Verification**: Automatically checks and displays the actual object type before attempting access to help prevent type mismatch errors
- Use the same connection arguments as MQbrowse.py.
- Use `--keystoretype PKCS12` for PFX/P12 files, `PEM` for PEM files, or `JKS` for JKS files (default).
- Use `--debug-tls` to enable verbose TLS handshake debugging for troubleshooting connection issues.
- Use `--disable-cert-verification` to bypass server certificate validation (useful for testing with self-signed certs).
- The tool will prompt for the keystore password (except for PEM files, which don't require passwords).
- The `--file` argument specifies the log file to replay (one message per file, as produced by MQbrowse.py).

**Log File Format:**
- Each log file contains the raw, unaltered bytes of a single message, as produced by MQbrowse.py.
- MQwrite.py writes the contents of the file as a single message to the queue.

## Troubleshooting TLS/SSL Issues

All tools include comprehensive TLS debugging and certificate bypass options:

- **`--debug-tls`**: Enables verbose SSL/TLS handshake debugging output to diagnose connection issues
- **`--disable-cert-verification`**: Bypasses all server certificate validation (useful for testing with self-signed certificates or untrusted CAs)

**Common TLS troubleshooting scenarios:**
```bash
# Debug TLS handshake issues
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --debug-tls

# Test with self-signed certificates
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --disable-cert-verification

# Combine debugging with certificate bypass
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --debug-tls --disable-cert-verification
```

These tools are useful for capturing and replaying MQ traffic for testing, troubleshooting, or security research.

## License
GNU General Public License v3.0 or later

## Author
Garland Glessner <gglessner@gmail.com> 