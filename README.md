Prerequisite a .pem cert file.  It can be generated using the follwing instructions:

$ openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem

  Country Name (2 letter code) [XX]:US
  State or Province Name (full name) []:OK
  Locality Name (eg, city) [Default City]:Oklahoma City
  Organization Name (eg, company) [Default Company Ltd]:shaw
  Organizational Unit Name (eg, section) []:shaw
  Common Name (eg, your name or your server's hostname) []:phil
  Email Address []:posop@hotmail.com


Build the Server file and run it:
 
$ make --file=mfs && ./server 5555


Build and run the client application

$ make --file=mfc && ./client 127.0.0.1 5555
