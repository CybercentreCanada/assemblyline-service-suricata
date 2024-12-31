[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_suricata-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-suricata)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-suricata)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-suricata)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-suricata)](./LICENSE)
# Suricata Service

This service scans network capture files with signature and extract files from network capture.

## Service Details

The Suricata configuration file is available in suricata\_.conf.suricata.yaml.

The ruleset(s) configured by default for use with this service are:

- [Emerging Threats Open](https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz)
- [Snortv3 Community](https://www.snort.org/downloads/community/snort3-community-rules.tar.gz)
- [URLhaus](https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz)

Organizations can add their own rulesets to this service.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Suricata \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-suricata

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Suricata

Ce service analyse les fichiers de capture réseau avec signature et extrait les fichiers de la capture réseau.

## Détails du service

Le fichier de configuration de Suricata est disponible dans suricata\_.conf.suricata.yaml.

Le(s) jeu(x) de règles configuré(s) par défaut pour être utilisé(s) avec ce service sont :

- [Emerging Threats Open](https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz)
- [Snortv3 Community](https://www.snort.org/downloads/community/snort3-community-rules.tar.gz)
- [URLhaus](https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz)

Les organisations peuvent ajouter leurs propres jeux de règles à ce service.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Suricata \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-suricata

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
