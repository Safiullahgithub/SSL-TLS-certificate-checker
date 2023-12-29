import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
from colorama import Fore, Style


def scan_ssl_cert(hostname, ports=(443, 80)):
    # Create an SSL context to configure the SSL/TLS connection
    context = ssl.create_default_context()

    try:
        # Remove the protocol prefix if present
        parsed_url = urlparse(hostname)
        if parsed_url.scheme:
            hostname = parsed_url.netloc

        # Resolve the hostname to an IP address
        ip_address = socket.gethostbyname(hostname)

        for port in ports:
            # Check if the URL is accessible over HTTP or HTTPS
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{hostname}:{port}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    print(f"The URL {url} is accessible and returns a status code of 200.")
                else:
                    print(f"The URL {url} is accessible but returns a status code of {response.status_code}.")
            except requests.RequestException as e:
                print(f"Failed to connect to {url}: {e}")

        # Continue with SSL certificate checking for port 443
        with socket.create_connection((ip_address, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the server's SSL certificate
                cert = ssock.getpeercert()

                # Check certificate expiration
                expiration_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if expiration_date < datetime.datetime.now():
                    print(f"The SSL certificate for {hostname} has expired on {expiration_date}.")
                else:
                    print(f"The SSL certificate for {hostname} is valid until {expiration_date}.")

                # Check for weak cipher suites
                cipher_suite = ssock.cipher()[0]
                if cipher_suite in ['RC4', 'DES', '3DES']:
                    print(f"The SSL/TLS cipher suite {cipher_suite} is considered weak.")
                else:
                    print(f"The SSL/TLS cipher suite {cipher_suite} is secure.")

                # Check for misconfigured certificates
                if cert['issuer'] == cert['subject']:
                    print(f"The SSL certificate for {hostname} is self-signed, which might indicate a misconfiguration.")

                # Check security strength of the certificate
                security_strength = cert.get('signatureAlgorithm', 'Unknown')
                print(f"The security strength of the SSL certificate for {hostname} is {security_strength}.")

    except socket.gaierror as e:
        print(f"Failed to resolve hostname {hostname}: {e}")


if __name__ == "__main__":
    # Print the author's name in large golden letters
    print(Fore.YELLOW + Style.BRIGHT + " Author Safi Ullah Khan" + Style.RESET_ALL)
   # print("Author: Safi Ullah Khan")
    print()

    # Get the target host from the user
    target_host = input("Enter the target host: ")
    scan_ssl_cert(target_host)
