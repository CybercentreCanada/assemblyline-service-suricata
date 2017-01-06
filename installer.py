#!/usr/bin/env python

import os


def install(alsi):
    alsi.sudo_apt_install([
        'oinkmaster',
        'libpcre3',
        'libpcre3-dbg',
        'libpcre3-dev',
        'build-essential',
        'autoconf',
        'automake',
        'libtool',
        'libpcap-dev',
        'libnet1-dev',
        'libyaml-0-2',
        'libyaml-dev',
        'zlib1g',
        'zlib1g-dev',
        'libcap-ng-dev',
        'libcap-ng0',
        'make',
        'libmagic-dev',
        'libjansson-dev',
        'libjansson4',
        'pkg-config'
    ])

    alsi.pip_install_all(['simplejson', 'python-dateutil'])

    directories = [
        '/var/run/suricata',
        '/etc/suricata',
        '/etc/suricata/rules',
        '/var/log/suricata'
    ]

    if not os.path.exists("/usr/local/bin/suricata"):
        src = 'suricata-3.1.2.tar.gz'
        remote_path = os.path.join('suricata/' + src)
        local_path = os.path.join('/tmp/', src)

        # Grab it from my file share for testing instead of the al repo
        alsi.fetch_package(remote_path, local_path)

        # configure and build suricata
        alsi.runcmd('sudo tar -C /tmp/ -xzf ' + local_path)
        src_path = local_path[:-7]
        alsi.runcmd('cd %s && sudo ./configure --prefix=/usr/local/ --sysconfdir=/etc/ --localstatedir=/var/ '
                   '&& sudo make -C %s && sudo make -C %s install && sudo ldconfig' % (src_path, src_path, src_path))
        alsi.runcmd('sudo rm -rf %s %s' % (src_path, local_path))

    # create directories
    for directory in directories:
        alsi.runcmd('sudo mkdir -p  %s' % directory)
        alsi.runcmd('sudo chown -R %s %s' % (alsi.config['system']['user'], directory))

    alsi.runcmd('sudo cp %s %s' %
               (os.path.join(alsi.alroot, 'pkg', 'al_services', 'alsvc_suricata', 'conf', 'suricata.yaml'),
                '/etc/suricata/'))
    alsi.runcmd('sudo chown %s /etc/suricata/suricata.yaml' % alsi.config['system']['user'])

    # copy config into position
    home_net = alsi.config['services']['master_list']['Suricata']['config']['HOME_NET']
    home_net = home_net.replace('/', '\/').replace('[', '\[').replace(']', '\]')
    alsi.sudo_sed_inline('/etc/suricata/suricata.yaml', ['s/__HOME_NET__/{home_net}/g'.format(home_net=home_net)])

    rules_url = alsi.config['services']['master_list']['Suricata']['config']['RULES_URL']
    rules_url = rules_url.replace('/', '\/').replace('[', '\[').replace(']', '\]').replace(':', '\:')

    alsi.runcmd("sudo /usr/sbin/oinkmaster -Q -u %s -o /etc/suricata/rules" % rules_url)
    alsi.runcmd("sudo touch /etc/suricata/oinkmaster")
    alsi.runcmd('sudo chown -R %s /etc/suricata/rules' % alsi.config['system']['user'])
    alsi.runcmd('sudo chown %s /etc/suricata/oinkmaster' % alsi.config['system']['user'])


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller

    install(SiteInstaller())
