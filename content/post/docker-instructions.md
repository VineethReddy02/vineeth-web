
{
  "title": "All About Docker Instructions",
  "date": "2019-07-02T09:32:45-04:00",
  "image": "/img/circleci-workflow.webp",
  "image": "/img/aafb-agent-ids-match-bamboo.webp",
  "description": "",
  "tags": ["Docker", "Containers", "DevOps"],
  "fact": "",
  "featured": false
}

<br/>

![Docker](/docker.jpg)

The main intention behind writing this blog is to understand docker instructions and it's capabilities while writing a Dockerfile.

In the recent past it's hard to find an application without a Dockerfile. 😃

- INSTRUCTIONS used in Dockerfile
    - FROM
    - MAINTAINER
    - RUN
    - CMD
    - LABEL
    - EXPOSE
    - ENV
    - ADD
    - COPY
    - ENTRYPOINT
    - VOLUME
    - USER
    - WORKDIR
    - ARG
    - ONBUILD
    - STOPSIGNAL
    - HEALTHCHECK
    - SHELL


### FROM 

```
FROM <image>                # picks latest by default
FROM <image>:<tag>          # specific version can be pulled
FROM <image>@<digest>       # This makes sure we pull the specific image with provided digest, 
                            # If image content is changed digest also changes.
```


- FROM cmd can be used multiple times in the same Dockerfile to build multiple images. This generates unique Id for each image.


```
 FROM alpine:3.5
 FROM python
 FROM vineeth97/saanvidashboard@sha256:ff6893d0750268ecfcdbe1e4a4d6f70b1a2ef43c5054ff11da0d5bc3595a79ec
```



### MAINTAINER


MAINTAINER <name>


- This is deprecated as docker LABEL instruction does exactly the same.

```
FROM alpine
MAINTAINER vineeth
```


### LABEL


LABEL ABC="XYZ" DEF="MNO"
LABEL ABC="XYZ"  \
              DEF="MNO"  \
              GHI="PQR"


- The LABEL cmd adds metadata to an image. A LABEL is a key-value pair. 
- If same key has different values the last occurring will take the precedence.

```
FROM alpine:3.3
LABEL fruit="APPLE" \
      vegetable="TOMATO" \
      fruit="BANANA"
LABEL abc="DEF" hjk="PQR"
```



### RUN

```
RUN ["npm","start"]   # exec form
RUN npm start         # shell form
```


Difference between shell form and exec form. By default shell form executes the commands in /bin/bash -c  context
But exec form needs explicit context to be set. As it doesn't pick /bin/bash -c by default.

```
FROM ubuntu
RUN apt-get update -y
ENV myName="John Doe" myDOg=Rex\ The\ Dog \
        myCat=fluffy
ENTRYPOINT ["/bin/bash","-c","echo $myName"] or ENTRYPOINT echo $myName
```

The above docker instrctions are combination of shell and exec form in the ENTRYPOINT instruction.




### CMD

```
CMD ["executable","param1","param2"] (exec form this is preferred form)
CMD ["param1","param2"] (used to provide default parameters to ENTRYPOINT])
CMD <command> <param1> <param2>
```

- CMD is used to provide a instruction to Dockerfile which also can overwritted using docker run cmd, Also used to provide defaults to the 
  ENTRYPOINT cmd this defaults are also overwritted using docker run cmd .


### ENTRYPOINT

- Difference between CMD and ENTRYPOINT, CMD is used only once if it's provided multiple times last provided one will take precedence. CMD is     overwritted when we pass any command with docker run IMAGENAME XYZ ENTRYPOINT is used as the command which cannot be overwritten. But we can    append parameters to the ENTRYPOINT either by CMD after ENTRYPOINT in Dockerfile or else by passing from docker run command.

```
FROM ubuntu
ENTRYPOINT ["echo"]
CMD ["VINEETH"]
```

In the above docker instruction CMD instruction is taken by default if any string is provided with docker run IMAGENAME XYZ will override the default CMD. 
If no CMD is provided. Any command provided with docker run will be appended to ENTRYPOINT command.


### SHELL


- The SHELL instruction is particularly used on windows. where there are two commonly used and quite different native shells: CMD and 
  POWERSHELL. as well as alternate shells available including sh. 
- The SHELL instruction can be used multiple times. But the previous SHELL instruction is ignored and current SHELL instruction affects all the 
  subsequent instructions.

```
FROM microsoft/windowsservercore

# Executed as cmd /S /C echo default
RUN echo default

# Executed as cmd /S /C powershell -command Write-Host default
RUN powershell -command Write-Host default

# Executed as powershell -command Write-Host hello
SHELL ["powershell", "-command"]
RUN Write-Host hello

# Executed as cmd /S /C echo hello
SHELL ["cmd", "/S", "/C"]
RUN echo hello

```

### HEALTHCHECK


- HEALTHCHECK instruction is used to check the health of the container based on some validations. This lets us know whether the container is
  not only just up and running but also serving the requests as intended.

```
FROM node:latest
COPY ./ ./app
EXPOSE 4200
WORKDIR /app
RUN npm install
#STOPSIGNAL SIGKILL
#HEALTHCHECK CMD sleep 50
HEALTHCHECK --interval=1s --timeout=1s --retries=1 CMD curl --fail http://localhost:4200/ || exit 1
CMD ["npm","start"]
```


--interval is used to check for time interval in checking the health
--timeout is used to limit the timeout for each check
--retries set retries to confirm unhealthy upon specific consecutive failures




### STOPSIGNAL


- STOPSIGNAL instruction is used to pass a signal to the container when we try stopping the container with docker stop it executes SIGTERM (this gives the graceful time to terminate the process if not it will kill the process) and docker kill executes SIGQUIT or SIGKILL.

```
FROM ubuntu
STOPSIGNAL SIGKILL
CMD ["sleep","5000"]
```
    
### ADD


- ADD instruction is used same as COPY instruction but it has some additional functionalities such as ADD from remote URL, extracting the tar from the host machine to docker image during build without multiple instruction which in return creates the multiple layers besides from this functionalities it also does all functionalities COPY instruction does.

```
FROM ubuntu
RUN mkdir node
ADD node-v8.10.0-linux-x64.tar.xz /node
ADD https://nodejs.org/dist/v8.10.0/node-v8.10.0-linux-x64.tar.xz .
CMD ["sleep",5000"]
```


### COPY


- COPY instruction is used to copy data from host machine to container. With COPY instruction we specify the src and destination.    

```
FROM ubuntu
COPY . .
CMD ["sleep","5000"]
```

### ENV


- ENV instruction is used to pass the environment varibales to the container runtime. It works same as environment variables in host level.

```
FROM ubuntu
ENV myName="John Doe" myDOg=Rex\ The\ Dog \
        myCat=fluffy
ENTRYPOINT ["/bin/bash","-c","echo $myName"]
```

### ARG


- ARG instruction is used to pass dynamic values during docker build with 
  docker build --build-arg VALUE=1.0   
- ARG instruct can optionally contain default value if no value is passed during docker build.
- When both ARG and ENV is used with same name ENV will override the ARG.

```
FROM ubuntu
ARG app=nodejs
RUN apt-get update && apt-get install -y $app
CMD ["sleep","5000"]
```

Above ARG instruction can we overrided during the build time using docker build --build-arg app=python . In the above docker instructions app = nodejs, But this can be overrided using docker build.


### ONBUILD


- ONBUILD instruction is used to perform an action on the image which uses it as base image. Triggers are inherited by the "child" build only. In other words, they are not inherited by "grand-children" builds.
- The ONBUILD instruction may not trigger FROM, MAINTAINER, or ONBUILD instructions.

```
FROM ubuntu
ONBUILD RUN mkdir VINEETH
```

The above docker image will create VINEETH directory to all the images which use the above image as base image. i.e Build the above image using 

```
docker build -t vineeth  .
```

This image on build will perform the action which is mentioned in the base image with ONBUILD instruction. i.e

```
RROM vineeth
```


### WORKDIR

- WORKDIR instruction is used to predefine the current directory in which build CMD, RUN instructions needs to be executed on. Even when we bash into the container we get into the WORKDIR by default.

```
FROM ubuntu
RUN ["mkdir","sample"]
WORKDIR sample/
ADD https://nodejs.org/dist/v8.10.0/node-v8.10.0-linux-x64.tar.xz .
CMD ["sleep","5000"]
```

### USER


- USER instruction is used to set the default user to the container and this gets validated and impacted when we run the container. Even if a user is invalid build succeeds. This instruction teakes action during docker run step.

```
FROM ubuntu
RUN useradd -ms /bin/bash  vineeth
USER vineeth
CMD ["sleep","500"]

```
### Tips
- During docker build the docker cli tries sending the entire content of Dockerfile directory to the docker daemon to increase the build’s performance, exclude files and directories by adding a .dockerignore file to the context directory.
- Starting with version 18.09, Docker supports a new backend for executing your builds that is provided by the moby/buildkit project. The BuildKit backend provides many benefits compared to the old implementation. To use the BuildKit backend, you need to set an environment variable DOCKER_BUILDKIT=1 on the CLI before invoking docker build.
