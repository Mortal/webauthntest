```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -nodes -subj /CN=localhost
npm i
./node_modules/.bin/ts-node-esm src/server.ts 
```
