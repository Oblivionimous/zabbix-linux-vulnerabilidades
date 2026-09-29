# Particularidades por sistema operacional

O script é o mesmo em todos os sistemas. Esta página reúne o que muda no entorno de cada distribuição, observado durante o piloto.

## Rocky Linux, RHEL e Alma

Validado em Rocky Linux 9.8 com o agente Zabbix agent2.

| Assunto | Detalhe |
|---|---|
| Fonte dos avisos | `dnf updateinfo list --security` e `--with-cve` |
| Reboot pendente | Depende do `needs-restarting` do pacote `yum-utils`. Sem ele o valor é -1 |
| Nome dos kernels | `kernel`, `kernel-core`, `kernel-modules`, `kernel-modules-core` |
| Pacotes de segurança | Avisos separados em Critical, Important, Moderate e Low |

O instalador instala o `yum-utils`. Se o `dnf` retornar erro de metadados de um repositório de terceiros, os comandos `dnf updateinfo` também falham. Em um host do piloto isso ocorreu porque o repositório `pkg.aquasec.com` não resolvia por DNS. A solução foi remover o arquivo `.repo` e instalar o trivy pelo pacote da release.

## Debian

Validado em Debian 13 (trixie).

| Assunto | Detalhe |
|---|---|
| Fonte dos avisos | Simulação `apt-get -s dist-upgrade`, contando entradas de `-security` |
| Reboot pendente | Existência de `/var/run/reboot-required` |
| Avisos por severidade | Não existem. Os itens gravam -1 e exibem `N/D (apt)` |
| Pacote `sudo` | Pode não estar instalado em instalações mínimas. Use `runuser` ou `su -s /bin/sh zabbix -c` para testar a leitura |

### Pacotes órfãos depois de upgrade de versão

Em um host atualizado de Debian 12 para 13 o trivy apontou CVEs corrigíveis em pacotes que o `apt` não oferecia atualizar. A causa eram pacotes da versão anterior ainda instalados, sem repositório de origem e sem nada que dependesse deles.

O sinal é uma tabela de versões do `apt-cache policy` com uma única linha e origem `/var/lib/dpkg/status`.

```bash
apt-cache policy NOME_DO_PACOTE
apt-cache rdepends --installed NOME_DO_PACOTE
apt-get -s purge NOME_DO_PACOTE
```

Se a dependência reversa estiver vazia e a simulação remover apenas o pacote esperado, o purge é seguro. Sempre confira a simulação antes.

## Ubuntu

Validado em Ubuntu 24.04 LTS com o agente clássico zabbix-agent.

| Assunto | Detalhe |
|---|---|
| Nome dos kernels | `linux-image-*`, `linux-modules-*`, `linux-headers-*` e também `linux-tools-*` |
| Volume de achados | O Ubuntu registra muitas CVEs de kernel. Um host chegou a 26 mil achados de kernels antigos, todos descartados pelo filtro |
| Agente clássico | O arquivo de configuração é `/etc/zabbix/zabbix_agentd.conf`, não `zabbix_agent2.conf` |

O prefixo `linux-tools-` precisa estar na lista de kernel. Sem ele, o pacote do kernel antigo continua no ranking e gera falsas CVEs corrigíveis. Isso está coberto em `tests/test_collect.py`.

## Proxmox VE

Validado em Proxmox VE 9 sobre Debian 13.

| Assunto | Detalhe |
|---|---|
| Nome dos kernels | `proxmox-kernel-*` e `pve-kernel-*`, no lugar de `linux-image-*` |
| Armazenamento | Discos de VM em LVM thin não aparecem no sistema de arquivos e não são varridos. Diretórios de ISOs e backups devem entrar em `extra-skip-dirs` |
| Carga de terceiros | Hosts que executam VMs de produção merecem `CPU_QUOTA` menor |
| ZFS | Pacotes de versões antigas de `libzpool` e `spl` podem sobrar depois de atualizações |

Exemplo de `/etc/zabbix-vuln/extra-skip-dirs` em um hypervisor.

```
/var/lib/vz
/nvme
```
