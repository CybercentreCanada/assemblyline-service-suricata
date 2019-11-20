FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH suricata.suricata.Suricata

RUN apt-get update && apt-get install -y \
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
  libnss3-dev

RUN pip install \
  simplejson \
  python-dateutil \
  suricata-update

# Switch to assemblyline user
USER assemblyline

# Copy Suricata service code
WORKDIR /opt/al_service
COPY . .