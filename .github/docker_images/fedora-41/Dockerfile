# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

FROM fedora:41

RUN dnf install -y qemu-user-static mock
RUN useradd mockbuilder
RUN usermod -a -G mock mockbuilder \
    && chmod -R g+w /etc/mock

COPY aws_lc_rs_build.sh /
COPY entry.sh /

ENV AWS_LC_RS_DISABLE_SLOW_TESTS=1
ENV CFLAGS="-O2 -Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3"

USER root
ENTRYPOINT ["/entry.sh"]
