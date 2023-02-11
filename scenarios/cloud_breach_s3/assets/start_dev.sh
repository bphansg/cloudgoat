#/usr/bin/env bash

# Build and start the container listening on 1389 and 8888 with code mounted in /app for development

IMAGE=l4jattack
CONTAINER=l4jattack

docker build -t $IMAGE:latest .
docker container rm $CONTAINER -f
docker run -d --name $CONTAINER -v /home/paloalto/log4j-attacker:/app -p 1389:1389 -p 8888:8888 $IMAGE:latest