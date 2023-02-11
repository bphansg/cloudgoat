# Using a newer version of java than the web app will prevent the exploit from loading 
# Stage 1 - build the java exploit
FROM openjdk:8u252-jdk
RUN mkdir /app
WORKDIR /app
COPY exploit.java .
RUN javac exploit.java

# Stage 2 - Build the python app image
FROM python:3.10
RUN mkdir /app && mkdir /app/data
WORKDIR /app
COPY --from=0 /app/exploit.class /app/data/exploittemplate.class
COPY . .
RUN pip install -r requirements.txt

CMD ["python3", "run.py"]
