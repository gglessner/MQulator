This directory must contain the following JAR files required by MQulator:

1. com.ibm.mq.allclient-9.4.1.0.jr
   - Download from IBM's official site (requires IBM ID):
     https://www.ibm.com/products/mq/downloads
   - Look for "IBM MQ classes for Java and JMS" or "Client" package.

2. json-20240303.jar
   - Download from Maven Central:
     https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar

3. javax.jms-api-2.0.1.jar
   - Download from Maven Central:
     https://repo1.maven.org/maven2/javax/jms/javax.jms-api/2.0.1/javax.jms-api-2.0.1.jar

Place all three JAR files in this directory before running MQulator. 