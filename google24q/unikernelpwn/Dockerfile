
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat
RUN apt-get -y install binutils
ADD chal chal
ADD flag /flag

EXPOSE 1337

#CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./chal"

