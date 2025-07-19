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

Place all three JARs in the `./lib/` directory as follows:
```
./lib/com.ibm.mq.allclient-9.4.1.0.jr   # (rename as needed to match your version)
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
  ```

## Error Handling and Reason Code Lookup

When an IBM MQ error occurs, MQulator will attempt to extract the MQ reason code from the exception and print a friendly, deciphered explanation for common codes (e.g., 2033 = MQRC_NO_MSG_AVAILABLE, 2058 = MQRC_Q_MGR_NAME_ERROR, etc.).

The reason code lookup table is easily extensible in the source code (`MQ_REASON_CODES` dictionary in `MQulator.py`). If you encounter a code not listed, you can add it to the table for more descriptive error messages.

## Additional Tools

### MQbrowse.py
A simple tool to browse messages from a single IBM MQ queue and log them for later replay. It connects to the specified queue and writes each raw message to a timestamped file in the `logs` directory. The log file is named with the queue and timestamp, and contains the raw, unaltered message bytes (suitable for re-injection).

**Example usage:**
```
python MQbrowse.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1
```

- Use `--truststore` if you want a different truststore; otherwise, the keystore is used for both.
- Use `--ciphersuite` to override the default TLS cipher suite.
- The tool will prompt for the JKS password.
- Messages are logged to `logs/QUEUE1_YYYYMMDD_HHMMSS.log`.

### MQwrite.py
A companion tool to write raw messages (as logged by MQbrowse.py) back to an IBM MQ queue. It reads a log file from the `logs` directory and writes its contents as a message to the specified queue.

**Example usage:**
```
python MQwrite.py --keystore mycert.jks --server host:port --qm QM1 --channel CHANNEL1 --queue QUEUE1 --file logs/QUEUE1_YYYYMMDD_HHMMSS.log
```

- Use the same connection arguments as MQbrowse.py.
- The tool will prompt for the JKS password.
- The `--file` argument specifies the log file to replay.

**Log File Format:**
- Each log file contains the raw, unaltered bytes of each message, concatenated in the order they were browsed.
- Currently, MQwrite.py writes the entire file as a single message. (Support for multiple messages per file can be added if needed.)

These tools are useful for capturing and replaying MQ traffic for testing, troubleshooting, or security research.

## License
GNU General Public License v3.0 or later

## Author
Garland Glessner <gglessner@gmail.com> 