#!/usr/bin/env python3
"""
IBM MQ REST API Client
A much simpler alternative to the Java-based MQ clients

Author: Garland Glessner <gglessner@gmail.com>
"""

import argparse
import requests
import json
import sys
import os
import tempfile
import subprocess
import getpass
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings when using --insecure
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def detect_cert_format(cert_file):
    """Detect certificate format based on file extension and content"""
    if not os.path.exists(cert_file):
        raise FileNotFoundError(f"Certificate file not found: {cert_file}")
    
    # Check by file extension first
    cert_file_lower = cert_file.lower()
    if cert_file_lower.endswith(('.jks', '.keystore')):
        return 'JKS'
    elif cert_file_lower.endswith(('.pfx', '.p12')):
        return 'PKCS12'
    elif cert_file_lower.endswith(('.pem', '.crt', '.cer', '.key')):
        return 'PEM'
    
    # If extension is unclear, try to detect by content
    try:
        with open(cert_file, 'rb') as f:
            header = f.read(100)
        
        if b'-----BEGIN' in header:
            return 'PEM'
        elif header.startswith(b'\xfe\xed\xfe\xed') or header.startswith(b'\xce\xce\xce\xce'):
            return 'JKS'  
        elif header.startswith(b'0\x82') or header.startswith(b'0\x83'):
            return 'PKCS12'
    except:
        pass
    
    # Default assumption
    return 'PEM'

def convert_cert_to_pem(cert_file, password=None):
    """Convert JKS/PKCS12 certificates to temporary PEM files"""
    cert_format = detect_cert_format(cert_file)
    
    if cert_format == 'PEM':
        return cert_file, None  # No conversion needed
    
    print(f"Detected {cert_format} certificate format, converting to PEM...")
    
    # Create temporary files
    temp_pem = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
    temp_pem.close()
    
    try:
        if cert_format == 'PKCS12':
            # Convert PKCS12 to PEM
            cmd = [
                'openssl', 'pkcs12', 
                '-in', cert_file,
                '-out', temp_pem.name,
                '-nodes'  # Don't encrypt private key
            ]
            
            if password:
                cmd.extend(['-passin', f'pass:{password}'])
            else:
                cmd.extend(['-passin', 'stdin'])
            
            print("Converting PKCS#12 to PEM format...")
            if password:
                result = subprocess.run(cmd, capture_output=True, text=True)
            else:
                # Prompt for password if not provided
                cert_password = getpass.getpass("Enter certificate password: ")
                result = subprocess.run(cmd, input=cert_password, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"PKCS#12 conversion failed: {result.stderr}")
                
        elif cert_format == 'JKS':
            # Convert JKS to PKCS12 first, then to PEM
            temp_p12 = tempfile.NamedTemporaryFile(suffix='.p12', delete=False)
            temp_p12.close()
            
            try:
                # Step 1: JKS to PKCS12
                jks_password = password or getpass.getpass("Enter JKS keystore password: ")
                
                cmd1 = [
                    'keytool', '-importkeystore',
                    '-srckeystore', cert_file,
                    '-srcstoretype', 'JKS',
                    '-destkeystore', temp_p12.name,
                    '-deststoretype', 'PKCS12',
                    '-srcstorepass', jks_password,
                    '-deststorepass', jks_password,
                    '-noprompt'
                ]
                
                print("Converting JKS to PKCS#12...")
                result1 = subprocess.run(cmd1, capture_output=True, text=True)
                if result1.returncode != 0:
                    raise Exception(f"JKS to PKCS#12 conversion failed: {result1.stderr}")
                
                # Step 2: PKCS12 to PEM
                cmd2 = [
                    'openssl', 'pkcs12',
                    '-in', temp_p12.name,
                    '-out', temp_pem.name,
                    '-nodes',
                    '-passin', f'pass:{jks_password}'
                ]
                
                print("Converting PKCS#12 to PEM...")
                result2 = subprocess.run(cmd2, capture_output=True, text=True)
                if result2.returncode != 0:
                    raise Exception(f"PKCS#12 to PEM conversion failed: {result2.stderr}")
                    
            finally:
                # Clean up temporary PKCS12 file
                try:
                    os.unlink(temp_p12.name)
                except:
                    pass
        
        print(f"✓ Certificate converted to PEM format: {temp_pem.name}")
        return temp_pem.name, True  # Return path and cleanup flag
        
    except Exception as e:
        # Clean up on failure
        try:
            os.unlink(temp_pem.name)
        except:
            pass
        raise Exception(f"Certificate conversion failed: {e}")

def main():
    parser = argparse.ArgumentParser(description='IBM MQ REST API Client')
    parser.add_argument('--server', required=True, help='MQ web server URL (e.g., https://mqserver:9443)')
    parser.add_argument('--qmgr', required=True, help='Queue Manager name')
    parser.add_argument('--queue', help='Queue name (for queue operations)')
    parser.add_argument('--topic', help='Topic string (for pub/sub operations)')
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication options')
    auth_group.add_argument('--username', help='Username for basic authentication')
    auth_group.add_argument('--password', help='Password for basic authentication')
    auth_group.add_argument('--cert', help='Client certificate file (PEM, JKS, or PKCS#12 format)')
    auth_group.add_argument('--key', help='Client private key file (PEM format, required with --cert for PEM)')
    auth_group.add_argument('--cert-bundle', help='Combined cert+key file (PEM format)')
    auth_group.add_argument('--cert-password', help='Password for JKS/PKCS#12 certificate files')
    
    parser.add_argument('--operation', required=True, 
                       choices=['browse', 'get', 'put', 'publish', 'subscribe', 'qinfo', 'qminfo'],
                       help='Operation to perform')
    parser.add_argument('--message', help='Message content (for put/publish operations)')
    parser.add_argument('--message-file', help='File containing message content')
    parser.add_argument('--output-dir', default='./messages', help='Directory to save browsed messages')
    parser.add_argument('--insecure', action='store_true', help='Skip SSL certificate verification')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--wait-time', type=int, default=5, help='Wait time for get/subscribe operations')
    
    args = parser.parse_args()
    
    # Validate authentication options
    if not any([args.username, args.cert, args.cert_bundle]):
        print("Error: Must provide either --username/--password OR --cert/--key OR --cert-bundle for authentication")
        sys.exit(1)
    
    if args.username and not args.password:
        print("Error: --password required when using --username")
        sys.exit(1)
    
    # For PEM certificates, key is required. For JKS/PKCS12, key is embedded
    if args.cert:
        cert_format = detect_cert_format(args.cert)
        if cert_format == 'PEM' and not args.key:
            print("Error: --key required when using PEM certificate format")
            sys.exit(1)
        elif cert_format in ['JKS', 'PKCS12'] and args.key:
            print("Warning: --key ignored for JKS/PKCS#12 certificates (key is embedded)")
        elif cert_format in ['JKS', 'PKCS12'] and not args.cert_password:
            print("Note: You may be prompted for certificate password")
    
    # Create MQ REST client
    client = MQRestClient(
        server_url=args.server,
        username=args.username,
        password=args.password,
        cert_file=args.cert,
        key_file=args.key,
        cert_bundle=args.cert_bundle,
        cert_password=args.cert_password,
        verify_ssl=not args.insecure,
        timeout=args.timeout
    )
    
    try:
        if args.operation == 'browse':
            if not args.queue:
                print("Error: --queue required for browse operation")
                sys.exit(1)
            client.browse_queue(args.qmgr, args.queue, args.output_dir)
            
        elif args.operation == 'get':
            if not args.queue:
                print("Error: --queue required for get operation")
                sys.exit(1)
            client.get_message(args.qmgr, args.queue, args.wait_time)
            
        elif args.operation == 'put':
            if not args.queue:
                print("Error: --queue required for put operation")
                sys.exit(1)
            message = get_message_content(args)
            client.put_message(args.qmgr, args.queue, message)
            
        elif args.operation == 'publish':
            if not args.topic:
                print("Error: --topic required for publish operation")
                sys.exit(1)
            message = get_message_content(args)
            client.publish_message(args.qmgr, args.topic, message)
            
        elif args.operation == 'subscribe':
            if not args.topic:
                print("Error: --topic required for subscribe operation")
                sys.exit(1)
            client.subscribe_topic(args.qmgr, args.topic, args.wait_time)
            
        elif args.operation == 'qinfo':
            if not args.queue:
                print("Error: --queue required for qinfo operation")
                sys.exit(1)
            client.get_queue_info(args.qmgr, args.queue)
            
        elif args.operation == 'qminfo':
            client.get_qmgr_info(args.qmgr)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        # Clean up any temporary certificate files
        client.cleanup()

def get_message_content(args):
    """Get message content from --message or --message-file"""
    if args.message:
        return args.message
    elif args.message_file:
        with open(args.message_file, 'r', encoding='utf-8') as f:
            return f.read()
    else:
        print("Error: Either --message or --message-file required for put/publish operations")
        sys.exit(1)

class MQRestClient:
    """IBM MQ REST API Client"""
    
    def __init__(self, server_url, username=None, password=None, cert_file=None, 
                 key_file=None, cert_bundle=None, cert_password=None, verify_ssl=True, timeout=30):
        self.base_url = server_url.rstrip('/') + '/ibmmq/rest/v3'
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.temp_files = []  # Track temporary files for cleanup
        
        # Configure authentication
        if username and password:
            # Basic authentication
            self.auth = (username, password)
            self.auth_type = "basic"
            print(f"Using basic authentication for user: {username}")
        elif cert_bundle:
            # Combined certificate and key file (PEM only)
            self.session.cert = cert_bundle
            self.auth = None
            self.auth_type = "cert"
            print(f"Using client certificate authentication: {cert_bundle}")
        elif cert_file:
            # Handle different certificate formats
            try:
                cert_format = detect_cert_format(cert_file)
                
                if cert_format == 'PEM' and key_file:
                    # Standard PEM cert + key
                    self.session.cert = (cert_file, key_file)
                    print(f"Using PEM client certificate: {cert_file} + {key_file}")
                elif cert_format in ['JKS', 'PKCS12']:
                    # Convert JKS/PKCS12 to PEM
                    temp_pem, needs_cleanup = convert_cert_to_pem(cert_file, cert_password)
                    if needs_cleanup:
                        self.temp_files.append(temp_pem)
                    self.session.cert = temp_pem
                    print(f"Using converted {cert_format} certificate (temporary PEM)")
                else:
                    raise ValueError(f"Unsupported certificate format: {cert_format}")
                
                self.auth = None
                self.auth_type = "cert"
                
            except Exception as e:
                raise ValueError(f"Certificate configuration failed: {e}")
        else:
            raise ValueError("Must provide authentication credentials")
        
        # Test connection
        self._test_connection()
    
    def _test_connection(self):
        """Test the connection to MQ REST API"""
        try:
            # Use auth only for basic authentication, cert auth is handled by session.cert
            auth_kwargs = {'auth': self.auth} if self.auth_type == "basic" else {}
            
            response = self.session.get(
                f"{self.base_url}/admin/installation",
                verify=self.verify_ssl,
                timeout=self.timeout,
                **auth_kwargs
            )
            if response.status_code == 200:
                print("✓ Connected to IBM MQ REST API")
            else:
                print(f"⚠ Connection test returned status {response.status_code}")
        except Exception as e:
            print(f"✗ Failed to connect to IBM MQ REST API: {e}")
            raise
    
    def _make_request(self, method, url, **kwargs):
        """Make an authenticated request using the configured session"""
        # Add auth for basic authentication, cert auth is handled by session.cert
        if self.auth_type == "basic":
            kwargs['auth'] = self.auth
        
        # Set default values
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        
        return self.session.request(method, url, **kwargs)
    
    def cleanup(self):
        """Clean up temporary certificate files"""
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
                print(f"Cleaned up temporary file: {temp_file}")
            except:
                pass
        self.temp_files = []
    
    def __del__(self):
        """Ensure cleanup on object destruction"""
        self.cleanup()
    
    def browse_queue(self, qmgr, queue, output_dir):
        """Browse messages in a queue without removing them"""
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"Browsing queue {queue} on {qmgr}...")
        
        msg_count = 0
        try:
            url = f"{self.base_url}/messaging/qmgr/{qmgr}/queue/{queue}/message"
            headers = {
                'ibm-mq-rest-csrf-token': 'value',
                'Accept': 'application/json'
            }
            
            while True:
                response = self._make_request(
                    'GET',
                    url,
                    headers=headers,
                    params={'properties': 'ALL'}
                )
                
                if response.status_code == 200:
                    msg_count += 1
                    
                    # Save message to file
                    msg_filename = os.path.join(output_dir, f"message_{msg_count:04d}.json")
                    with open(msg_filename, 'w', encoding='utf-8') as f:
                        json.dump(response.json(), f, indent=2)
                    
                    print(f"Message {msg_count}: {msg_filename}")
                    
                elif response.status_code == 404:
                    break
                else:
                    print(f"Error browsing: {response.status_code} - {response.text}")
                    break
                    
        except Exception as e:
            print(f"Error during browse: {e}")
        
        print(f"Browse complete. Found {msg_count} messages.")
    
    def get_message(self, qmgr, queue, wait_time=5):
        """Get (consume) a message from a queue"""
        print(f"Getting message from queue {queue} on {qmgr}...")
        
        url = f"{self.base_url}/messaging/qmgr/{qmgr}/queue/{queue}/message"
        headers = {
            'ibm-mq-rest-csrf-token': 'value',
            'Accept': 'application/json'
        }
        
        response = self._make_request(
            'DELETE',
            url,
            headers=headers,
            params={'wait': wait_time * 1000},
            timeout=self.timeout + wait_time
        )
        
        if response.status_code == 200:
            msg_data = response.json()
            print("Message received:")
            print(json.dumps(msg_data, indent=2))
        elif response.status_code == 404:
            print("No messages available on the queue")
        else:
            print(f"Error getting message: {response.status_code} - {response.text}")
    
    def put_message(self, qmgr, queue, message):
        """Put a message onto a queue"""
        print(f"Putting message to queue {queue} on {qmgr}...")
        
        url = f"{self.base_url}/messaging/qmgr/{qmgr}/queue/{queue}/message"
        headers = {
            'ibm-mq-rest-csrf-token': 'value',
            'Content-Type': 'text/plain;charset=utf-8'
        }
        
        response = self._make_request(
            'POST',
            url,
            headers=headers,
            data=message
        )
        
        if response.status_code == 201:
            print("✓ Message successfully put onto queue")
            if 'Location' in response.headers:
                print(f"Message ID: {response.headers['Location']}")
        else:
            print(f"✗ Failed to put message: {response.status_code} - {response.text}")
    
    def publish_message(self, qmgr, topic, message):
        """Publish a message to a topic"""
        print(f"Publishing message to topic {topic} on {qmgr}...")
        
        url = f"{self.base_url}/messaging/qmgr/{qmgr}/topic/{topic}/message"
        headers = {
            'ibm-mq-rest-csrf-token': 'value',
            'Content-Type': 'text/plain;charset=utf-8'
        }
        
        response = self._make_request(
            'POST',
            url,
            headers=headers,
            data=message
        )
        
        if response.status_code == 201:
            print("✓ Message successfully published to topic")
        else:
            print(f"✗ Failed to publish message: {response.status_code} - {response.text}")
    
    def subscribe_topic(self, qmgr, topic, wait_time=5):
        """Subscribe to a topic and wait for messages"""
        print(f"Subscribing to topic {topic} on {qmgr}...")
        print("Waiting for messages (Ctrl+C to exit)...")
        
        url = f"{self.base_url}/messaging/qmgr/{qmgr}/topic/{topic}/message"
        headers = {
            'ibm-mq-rest-csrf-token': 'value',
            'Accept': 'application/json'
        }
        
        try:
            while True:
                response = self._make_request(
                    'DELETE',
                    url,
                    headers=headers,
                    params={'wait': wait_time * 1000},
                    timeout=self.timeout + wait_time
                )
                
                if response.status_code == 200:
                    msg_data = response.json()
                    print("Message received:")
                    print(json.dumps(msg_data, indent=2))
                    print("-" * 40)
                elif response.status_code == 404:
                    print(".", end="", flush=True)
                else:
                    print(f"Error: {response.status_code} - {response.text}")
                    break
                    
        except KeyboardInterrupt:
            print("\nSubscription ended by user")
    
    def get_queue_info(self, qmgr, queue):
        """Get information about a queue"""
        print(f"Getting information for queue {queue} on {qmgr}...")
        
        url = f"{self.base_url}/admin/qmgr/{qmgr}/queue/{queue}"
        
        response = self._make_request('GET', url)
        
        if response.status_code == 200:
            queue_info = response.json()
            print("Queue Information:")
            print(json.dumps(queue_info, indent=2))
        else:
            print(f"Error getting queue info: {response.status_code} - {response.text}")
    
    def get_qmgr_info(self, qmgr):
        """Get information about a queue manager"""
        print(f"Getting information for queue manager {qmgr}...")
        
        url = f"{self.base_url}/admin/qmgr/{qmgr}"
        
        response = self._make_request('GET', url)
        
        if response.status_code == 200:
            qmgr_info = response.json()
            print("Queue Manager Information:")
            print(json.dumps(qmgr_info, indent=2))
        else:
            print(f"Error getting queue manager info: {response.status_code} - {response.text}")

if __name__ == "__main__":
    main()
