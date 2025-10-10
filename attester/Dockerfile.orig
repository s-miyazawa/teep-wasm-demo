# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y install libcurl4-openssl-dev git gcc make libssl-dev

RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git /root/QCBOR
WORKDIR /root/QCBOR
RUN make libqcbor.a install

RUN git clone --branch dev-deterministic-ecdsa --depth 1 https://github.com/kentakayama/t_cose.git /root/t_cose
WORKDIR /root/t_cose
RUN make -f Makefile.ossl libt_cose.a install

WORKDIR /root
RUN git clone --depth 1 https://github.com/kentakayama/libteep.git /root/libteep
WORKDIR /root/libteep
RUN make -f Makefile.client

CMD sh -c "sleep 1 && ./bin/teep_http_client http://container_tam:8080/tam"
