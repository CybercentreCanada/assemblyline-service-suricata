FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH suricata_.suricata_.Suricata
ENV SURICATA_VERSION 4.1.2

RUN apt-get update && apt-get install -y \
  git \
  libpcre3 \
  libpcre3-dbg \
  libpcre3-dev \
  build-essential \
  autoconf \
  automake \
  libtool \
  libpcap-dev \
  libnet1-dev \
  libyaml-0-2 \
  libyaml-dev \
  zlib1g \
  zlib1g-dev \
  libcap-ng-dev \
  libcap-ng0 \
  make \
  libmagic-dev \
  libjansson-dev \
  libjansson4 \
  pkg-config \
  cargo \
  liblua5.1-dev \
  libnss3-dev \
  liblz4-dev

RUN pip install \
  gitpython \
  simplejson \
  python-dateutil \
  suricata-update \
  retrying

RUN wget -O /tmp/suricata-${SURICATA_VERSION}.tar.gz https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz
RUN tar -xvzf /tmp/suricata-${SURICATA_VERSION}.tar.gz -C /tmp
WORKDIR /tmp/suricata-${SURICATA_VERSION}
RUN ./configure --prefix=/usr/local/ --sysconfdir=/etc/ --localstatedir=/var/ --enable-python --enable-rust --enable-lua \
  && make -C /tmp/suricata-${SURICATA_VERSION} && make -C /tmp/suricata-${SURICATA_VERSION} install && ldconfig && \
  make -C /tmp/suricata-${SURICATA_VERSION} install-full
RUN mkdir -p /etc/suricata && chown -R assemblyline /etc/suricata
RUN mkdir -p /var/lib/suricata && chown -R assemblyline /var/lib/suricata
RUN mkdir -p /var/log/suricata && chown -R assemblyline /var/log/suricata
COPY suricata_/conf/suricata.yaml /etc/suricata/
RUN chown assemblyline /etc/suricata/suricata.yaml
RUN sed -i -e 's/__HOME_NET__/any/g' /etc/suricata/suricata.yaml

# Update local rules using suricata-update script here

RUN touch /etc/suricata/suricata-rules-update
RUN chown -R assemblyline /var/lib/suricata/
RUN chown assemblyline /etc/suricata/suricata-rules-update

COPY suricata_/stripe/* /tmp/stripe/
RUN /usr/bin/gcc -o /tmp/stripe/stripe /tmp/stripe/stripe.c
RUN cp /tmp/stripe/stripe /usr/local/bin/stripe

# Cleanup
RUN rm -rf /tmp/*

# Switch to assemblyline user
USER assemblyline

# Copy Suricata service code
WORKDIR /opt/al_service
COPY . .