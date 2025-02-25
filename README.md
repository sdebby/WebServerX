# Personal python Web Server

## Overview
This project started when a friend asked me to share a large file (17 GB) with him. The available options were not suitable:
1. Email - *Email has size limitations*
2. Split and send via email - *Would require splitting into 680 separate emails*
3. Upload to Google Drive/Dropbox - *Requires a paid account*
4. Share via torrent - *Too complicated for my friend and not working*

**Solution**
Create a secure file download web server and host it on my Raspberry Pi internally!

## MRD (Marketing requirement)
- A secure file download server.
- Easy to access with no additional software.
- Server will be online for a period of time.

## Technical

### How to use
* Creating a python secure web server, that display 2 HTML pages : login and files.  
* Configure the server by creating a certificate and placing it in `certs` folder and a public and privet key.  
* Put your shared files in the `files` folder.
* Send the public key to the client .
* Run the server with (or without) time limitation.
* Configure your router to route incoming port to your host IP
* On client connecting to the server IP address (on port 4433) the browser will display a "not secure page" this is due to the fact that the HTTPS certificate is self singed.
* The client then need to attach the provided public key file.
* After verification, the files page is sown to enable the client downloading. 

### Libraries
using the following libraries:
```
flask
werkzeug
pyOpenSSL
cryptography
```

To install run `pip install -r requirements.txt`

### Arguments
* To create a certificate (need OpenSSL to be installed)  
`python WebServer.py -c `

* To create a public and privet keys  
`python WebServer.py -k `

* To verify a public and privet keys  
`python WebServer.py -k `

* To run server with lime limit of 5 hours  
`python WebServer.py -r 5`

* Just run server for unlimited time  
`python WebServer.py`

### SSL certificate:
Run this to create a certificate using a command line 
```bash
cd certs
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```
**Note**: Since this uses self-signed certificates, browsers will show a security warning. You can use a proper certificates from a trusted Certificate Authority (like [Lets Encrypt](https://letsencrypt.org/)), Another option is to install the certificate into your OS system.

## Security measures implemented in the code
* Authentication - use a public key instead of user+password, public+privet keys can be replaced at any time.
* Input validation - validate privet key structure 
* Self certificate HTTPS - prevents packet sniffing and men in the middle attacks.
* Session time limit - Limits user time on page
* Time base server - server will be online for limited time
* Security headers like : SAME ORIGIN enabled, HTTPS enforce, XSS filtering, MIME sniffing prevention
* Brut-force protection - lock down period after failed attempts from same IP  
* Path Traversal Protection - ensuring that file paths are within the allowed directory to prevent path traversal attacks

## Skill set
* HTML
* HTTPS
* CSS
* Python
* Cyber-Security

## Feedback
If you have any feedback, please reach out at shmulik.debby@gmail.com
