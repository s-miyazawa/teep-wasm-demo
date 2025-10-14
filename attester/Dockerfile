FROM ubuntu:24.04

RUN apt-get update
RUN apt-get -y install libcurl4-openssl-dev git gcc make libssl-dev cmake g++

# build wasm-micro-runtime
WORKDIR /root/
RUN git clone https://github.com/bytecodealliance/wasm-micro-runtime
WORKDIR /root/wasm-micro-runtime/product-mini/platforms/linux/
RUN mkdir build
WORKDIR /root/wasm-micro-runtime/product-mini/platforms/linux/build
RUN cmake ..
RUN make
RUN make install

# build teep-attester
WORKDIR /root/
COPY . ./ietf124-teep-attester/

WORKDIR /root/ietf124-teep-attester/third_party/QCBOR
RUN make libqcbor.a install

WORKDIR /root/ietf124-teep-attester/third_party/t_cose
RUN make -f Makefile.ossl libt_cose.a install

WORKDIR /root/ietf124-teep-attester/third_party/libcsuit
RUN make -f Makefile libcsuit.a install

WORKDIR /root/ietf124-teep-attester/third_party/libteep
RUN make -f Makefile install

WORKDIR /root/ietf124-teep-attester
RUN make

ENV TAM_URL=http://container_tam:8080
WORKDIR /tmp
CMD sh -c "sleep 1 && teep_wasm_get install app.wasm"