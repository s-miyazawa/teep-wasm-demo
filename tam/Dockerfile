# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

COPY . .
RUN apt-get update
RUN apt-get -y install netcat-openbsd

CMD ["./tam_server.sh"]