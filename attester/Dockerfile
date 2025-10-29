FROM ubuntu:24.04

RUN apt-get update
RUN apt-get -y install libcurl4-openssl-dev git gcc make libssl-dev cmake g++ netcat-openbsd

# build wasm-micro-runtime
WORKDIR /root/
RUN git clone --depth 1 https://github.com/bytecodealliance/wasm-micro-runtime
WORKDIR /root/wasm-micro-runtime/product-mini/platforms/linux/
RUN mkdir build
WORKDIR /root/wasm-micro-runtime/product-mini/platforms/linux/build
RUN cmake ..
RUN make
RUN make install

# build teep-attester
WORKDIR /root/
COPY . ./ietf124-teep-attester/

WORKDIR /root/ietf124-teep-attester
RUN make 
RUN make install

#WORKDIR /root/ietf124-teep-attester/tests
WORKDIR /tmp
COPY .bash_history /root/.bash_history
ENV TAM_URL=http://container_tam:8080/tam
ENV PROFILE=generic

CMD sh -c "./tam_server.sh>/dev/null & sleep 1 && teep_wasm_get install app.wasm"

