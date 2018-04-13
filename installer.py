#!/usr/bin/env python

import os
import platform

# install using PPA built packages
# On internet connected machine:
# sudo add-apt-repository ppa:oisf/suricata-stable
# sudo apt-get update
# Then to download packages to upload separately to s3
# sudo apt-get install -d -o=dir::cache=/tmp suricata
# As far as I can tell, you should only need the libhtp2 and suricata .deb files


def install(alsi):

    # Install oinkmaster
    alsi.sudo_apt_install([
        'oinkmaster'
        ])

    # .deb packages to manually install
    deb_pkgs_ubt14 = ["libhiredis0.10_0.11.0-3_amd64.deb",  "libhtp2_1%3a0.5.26-2ubuntu4_amd64.deb", "suricata_4.0.4-2ubuntu4_amd64.deb"]
    deb_pkgs_ubt16 = ["libhtp2_1%3a0.5.26-2ubuntu3_amd64.deb", "suricata_4.0.4-2ubuntu3_amd64.deb"]

    (dist, ubt_version, name) = platform.linux_distribution()

    if ubt_version == "14.04":
        deb_pkgs = deb_pkgs_ubt14
    elif ubt_version == "16.04":
        deb_pkgs = deb_pkgs_ubt16

    # pull them down first
    for deb_pkg in deb_pkgs:
        alsi.fetch_package(os.path.join("suricata/", deb_pkg),
                           os.path.join("/tmp/", deb_pkg))

    local_paths = [os.path.join("/tmp/", deb_pkg) for deb_pkg in deb_pkgs]

    # now install them
    if ubt_version == "14.04":
        # Need to manually install some dependancies
        alsi.sudo_apt_install([
            "libluajit-5.1-2",
            "libluajit-5.1-common",
            "libmnl0",
            "libnetfilter-queue1"])
        for deb_pkg in local_paths:
            alsi.runcmd("sudo dpkg -i --force-confnew %s" % deb_pkg)

    # newer apt can install .deb files directly and handle dep resolution
    elif ubt_version == "16.04":
        alsi.sudo_apt_install(local_paths)

    # disable the service and make sure it's not running
    if ubt_version == "14.04":
        alsi.runcmd("sudo service suricata stop")
        alsi.runcmd("sudo update-rc.d -f suricata remove")
    elif ubt_version == "16.04":
        alsi.runcmd("sudo systemctl disable suricata")
        alsi.runcmd("sudo systemctl stop suricata")

    # clean up
    for deb_pkg in local_paths:
        alsi.runcmd('sudo rm -rf %s' % deb_pkg)

    alsi.pip_install_all(['simplejson', 'python-dateutil'])

    directories = [
        '/etc/suricata',
        '/etc/suricata/rules',
        '/var/log/suricata'
    ]

    # Create directories
    for directory in directories:
        alsi.runcmd('sudo mkdir -p  %s' % directory)
        alsi.runcmd('sudo chown -R %s %s' % (alsi.config['system']['user'], directory))

    alsi.runcmd('sudo cp %s %s' %
               (os.path.join(alsi.alroot, 'pkg', 'al_services', 'alsvc_suricata', 'conf', 'suricata.yaml'),
                '/etc/suricata/'))
    alsi.runcmd('sudo chown %s /etc/suricata/suricata.yaml' % alsi.config['system']['user'])

    # Copy the Suricata configuration into position
    home_net = alsi.config['services']['master_list']['Suricata']['config']['HOME_NET']
    home_net = home_net.replace('/', '\/').replace('[', '\[').replace(']', '\]')
    alsi.sudo_sed_inline('/etc/suricata/suricata.yaml', ['s/__HOME_NET__/{home_net}/g'.format(home_net=home_net)])

    rules_urls = alsi.config['services']['master_list']['Suricata']['config']['RULES_URLS']

    # Update our local rules using Oinkmaster
    rules_command = ["sudo", "/usr/sbin/oinkmaster", "-Q", "-o", "/etc/suricata/rules"]
    for rules_url in rules_urls:
        rules_command.extend(["-u",
                              rules_url.replace('/', '\/').replace('[', '\[').replace(']', '\]').replace(':', '\:')])
    alsi.runcmd(" ".join(rules_command))

    alsi.runcmd("sudo touch /etc/suricata/oinkmaster")
    alsi.runcmd('sudo chown -R %s /etc/suricata/rules' % alsi.config['system']['user'])
    alsi.runcmd('sudo chown %s /etc/suricata/oinkmaster' % alsi.config['system']['user'])

    # Build stripe, a tool to strip frame headers from PCAP files
    if not os.path.exists("/usr/local/bin/stripe"):
        stripe_path = os.path.join(alsi.alroot, 'pkg', 'al_services', 'alsvc_suricata', "stripe")
        alsi.runcmd('/usr/bin/gcc -o %s %s' % (os.path.join(stripe_path, 'stripe'), os.path.join(stripe_path, 'stripe.c')))
        alsi.runcmd('sudo cp %s %s' % (os.path.join(stripe_path, 'stripe'), '/usr/local/bin/stripe'))


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller

    install(SiteInstaller())
