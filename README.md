# MQulator

MQulator is a Python tool for browsing messages from IBM MQ queues using the IBM MQ Java client via JPype. It iterates through all combinations of servers, queue managers, channels, queues, and TLS certificates, connecting to each and displaying any messages found.

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
- Python packages: see `requirements.txt`

## Where to get the .jar files
- **IBM MQ allclient JAR**: Download from IBM's official site (requires IBM ID):
  - [IBM MQ Downloads](https://www.ibm.com/products/mq/downloads)
  - Look for "IBM MQ classes for Java and JMS" or "Client" package, which contains `mq.allclient-<version>.jar`.
- **JSON JAR**: Download from the official JSON.org site or Maven Central:
  - [https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar](https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar)

Place both JARs in the `./lib/` directory as follows:
```
./lib/com.ibm.mq.allclient-9.4.1.0.jr   # (rename as needed to match your version)
./lib/json-20240303.jar
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

## License
GNU General Public License v3.0 or later

## Author
Garland Glessner <gglessner@gmail.com> 