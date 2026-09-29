# Instalação

Há dois caminhos equivalentes. O instalador automático faz tudo em um comando. O caminho manual mostra cada etapa e serve para auditoria ou para ambientes sem acesso ao repositório.

## Pré-requisitos

- Acesso root ao host.
- Python 3 e systemd.
- Saída HTTPS para `github.com` e para os registros da base de vulnerabilidades do trivy.
- Agente Zabbix instalado em modo ativo, veja [zabbix.md](zabbix.md).

## Instalador automático

```bash
git clone https://github.com/SEU_USUARIO/zabbix-linux-vulnerabilidades.git
cd zabbix-linux-vulnerabilidades
RUN_NOW=1 ./scripts/install.sh
./scripts/validate.sh
```

O instalador executa estas ações.

1. Detecta a família do sistema pelo `/etc/os-release`.
2. Instala `jq` e, em RPM, `yum-utils` para o `needs-restarting`.
3. Baixa o pacote do trivy da versão fixa, valida o `sha256` e instala.
4. Copia o script para `/usr/local/sbin` com permissão `0750`.
5. Cria `/etc/zabbix-vuln/extra-skip-dirs` se ainda não existir.
6. Instala as units, aplica os limites informados e habilita o timer.
7. Executa uma coleta se `RUN_NOW=1`.

### Variáveis de ambiente

| Variável | Padrão | Uso |
|---|---|---|
| `TRIVY_VERSION` | `0.74.0` | Versão fixa do trivy |
| `ONCALENDAR` | `*-*-* 02:00:00` | Horário base do timer |
| `RANDOM_DELAY` | `3h` | Atraso aleatório somado ao horário |
| `CPU_QUOTA` | `50%` | Limite de CPU do service |
| `MEMORY_MAX` | `2G` | Limite de memória do service |
| `RUN_NOW` | `0` | Se 1, executa uma coleta ao final |

O instalador recusa as versões 0.69.4, 0.69.5 e 0.69.6 do trivy.

### Exemplo para host sensível

Em um host que também roda carga de produção, use limite menor e horário próprio.

```bash
CPU_QUOTA=30% ONCALENDAR="*-*-* 04:00:00" RUN_NOW=1 ./scripts/install.sh
```

### Escalonamento entre hosts

Use horários base diferentes para que os servidores não varram o disco ao mesmo tempo. O piloto usou 02h, 03h e 04h, cada um com até 3 horas de atraso aleatório.

## Instalação manual

Os comandos abaixo repetem o que o instalador faz. Execute como root.

### 1. Dependências

Em RHEL, Rocky e Alma.

```bash
dnf install -y jq yum-utils
```

Em Debian e Ubuntu.

```bash
apt-get update
apt-get install -y jq
```

### 2. Trivy com versão fixa e checksum

Em RHEL, Rocky e Alma.

```bash
VER=0.74.0
cd /tmp
curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${VER}/trivy_${VER}_Linux-64bit.rpm
curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${VER}/trivy_${VER}_checksums.txt
grep " trivy_${VER}_Linux-64bit.rpm\$" trivy_${VER}_checksums.txt | sha256sum -c - && dnf install -y ./trivy_${VER}_Linux-64bit.rpm
trivy --version | head -1
rm -f trivy_${VER}_Linux-64bit.rpm trivy_${VER}_checksums.txt
```

Em Debian e Ubuntu.

```bash
VER=0.74.0
cd /tmp
curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${VER}/trivy_${VER}_Linux-64bit.deb
curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${VER}/trivy_${VER}_checksums.txt
grep " trivy_${VER}_Linux-64bit.deb\$" trivy_${VER}_checksums.txt | sha256sum -c - && apt-get install -y ./trivy_${VER}_Linux-64bit.deb
trivy --version | head -1
rm -f trivy_${VER}_Linux-64bit.deb trivy_${VER}_checksums.txt
```

A linha do `sha256sum` deve terminar com `OK`. Se falhar, não instale.

O repositório `pkg.aquasec.com` não é usado de propósito. Em um dos hosts do piloto o nome não resolveu e o `dnf` inteiro passou a falhar até a remoção do arquivo `.repo`.

### 3. Script, configuração e units

```bash
install -m 0750 -o root -g root src/vuln-collect.py /usr/local/sbin/vuln-collect.py
mkdir -p /etc/zabbix-vuln
install -m 0644 config/extra-skip-dirs.example /etc/zabbix-vuln/extra-skip-dirs
install -m 0644 systemd/vuln-collect.service /etc/systemd/system/vuln-collect.service
install -m 0644 systemd/vuln-collect.timer /etc/systemd/system/vuln-collect.timer
systemctl daemon-reload
systemctl enable --now vuln-collect.timer
```

### 4. Primeira coleta

A primeira execução baixa a base de vulnerabilidades e demora mais.

```bash
systemctl start vuln-collect.service
systemctl status vuln-collect.service --no-pager | head -8
jq '{status, duration, fixable: .trivy.fixable}' /var/lib/zabbix-vuln/report.json
```

O service deve terminar com `status=0/SUCCESS`. O campo `status` do relatório deve ser `ok`.

## Ajustes por host

### Exclusões do trivy

Edite `/etc/zabbix-vuln/extra-skip-dirs` para ignorar diretórios que não contêm pacotes de sistema, como armazenamento de ISOs e backups em um hypervisor. O arquivo aceita uma linha por diretório e comentários iniciados por `#`.

Sem essa exclusão o trivy percorre arquivos grandes sem necessidade e a coleta demora.

### Limites de recurso

Para alterar os limites depois da instalação, edite as diretivas no arquivo do service e recarregue.

```bash
nano /etc/systemd/system/vuln-collect.service
systemctl daemon-reload
```

## Atualização

Para atualizar o script em um host, copie a nova versão e confira o hash.

```bash
install -m 0750 -o root -g root src/vuln-collect.py /usr/local/sbin/vuln-collect.py
sha256sum /usr/local/sbin/vuln-collect.py
```

O hash deve ser igual em todos os hosts. Consulte [operacao.md](operacao.md).

## Remoção

```bash
./scripts/uninstall.sh
./scripts/uninstall.sh --purge
```

A segunda forma remove também o relatório, a configuração e o cache do trivy. O pacote trivy não é removido em nenhum dos casos.
