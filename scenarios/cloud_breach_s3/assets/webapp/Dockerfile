FROM openjdk:8u252-jdk

RUN mkdir /app
WORKDIR /app
COPY . .

RUN cd /opt && \
    apt-get update && \
    apt-get -y install awscli && \
    wget https://dlcdn.apache.org/maven/maven-3/3.8.7/binaries/apache-maven-3.8.7-bin.tar.gz --no-check-certificate && \
    tar -xvf ./apache-maven-3.8.7-bin.tar.gz && \
    export PATH=$PATH:/opt/apache-maven-3.8.7/bin/ && \
    cd /app && \
    mvn -N wrapper:wrapper && \
    mvn package

# Ask Kevin
RUN touch /tmp/buildfile_2 && \
    rm /tmp/buildfile_2

ENV PATH="/opt/apache-maven-3.8.7/bin/${PATH}"

RUN apt-get update && apt-get -y install python3 python3-pip
RUN python3 -m pip install -r /app/frontend/requirements.txt

CMD ["sh", "start.sh"]
