# Operação

## Rotina

| Frequência | Atividade |
|---|---|
| Diária, automática | O timer executa a coleta |
| Semanal | Revisar Problems com a tag `scope: security` e o ranking de CVEs |
| Mensal | Conferir que o hash do script é o mesmo em todos os hosts |
| A cada nova versão do trivy | Ler o aviso de segurança da release antes de atualizar |

## Conferir a versão do script em todos os hosts

O hash esperado da versão 1.0.0 é este.

```
37ae12d322ea9bffca97210045b7c75a9093fb16d0a6ceb4f7fc685d23cc9210
```

Em cada host.

```bash
sha256sum /usr/local/sbin/vuln-collect.py
```

Ou, com o repositório clonado, `./scripts/validate.sh` compara com `src/vuln-collect.py` automaticamente. Um hash diferente indica uma cópia desatualizada ou editada à mão.

## Forçar uma coleta

```bash
systemctl start vuln-collect.service
journalctl -u vuln-collect.service -n 30 --no-pager
jq '{status, duration, fixable: .trivy.fixable}' /var/lib/zabbix-vuln/report.json
```

Use o service e não o script direto. Assim a coleta respeita o `Nice`, o `CPUQuota` e o limite de memória.

## Atualizar o trivy

1. Leia as notas da release e o histórico de avisos de segurança do projeto.
2. Escolha uma versão fixa, nunca a mais recente sem conferência.
3. Rode o instalador com a nova versão.

```bash
TRIVY_VERSION=X.Y.Z ./scripts/install.sh
```

O instalador valida o checksum. Depois rode `./scripts/validate.sh` e compare os números com os anteriores.

## Verificar a base de vulnerabilidades

A base fica em `/var/cache/trivy`. Para ver a data de atualização.

```bash
jq . /var/cache/trivy/db/metadata.json
```

Uma base velha faz o trivy deixar de ver CVEs recentes sem gerar erro. Este indicador ainda não é monitorado pelo template e consta no [roadmap](roadmap.md).

## Runbook por trigger

| Trigger | Significado | O que fazer |
|---|---|---|
| Coleta de vulnerabilidades com erro | O campo `status` do relatório não é `ok` | Ver `journalctl -u vuln-collect.service`, rodar a coleta manualmente, checar rede e disco |
| Coleta desatualizada | O relatório tem mais de 36 horas | Ver `systemctl list-timers vuln-collect.timer`, conferir o service e o espaço em disco |
| CVE CRITICAL corrigível em pacote do SO | Existe patch crítico não aplicado | Atualizar o pacote, reiniciar se necessário |
| CVEs HIGH corrigíveis em pacotes do SO acima do limite | Patches de severidade alta acumulados | Atualizar pacotes. Ajustar a macro por host se o limite não fizer sentido |
| CVE CRITICAL corrigível em aplicação | Biblioteca vulnerável embutida em um software | Atualizar o software, pois o gerenciador de pacotes do sistema não corrige |
| Advisory de segurança Critical pendente | Aviso crítico do fornecedor pendente | Aplicar atualização de segurança do sistema |
| Reboot pendente há mais de 7 dias | Atualizações instaladas aguardam reinício | Agendar reinício na próxima janela |
| Sem atualização de pacotes há mais de 60 dias | Servidor fora do ciclo de patch | Revisar o processo de atualização do host |

### Aplicar correções

Em RHEL, Rocky e Alma.

```bash
dnf updateinfo list security
dnf update --security -y
needs-restarting -r
```

Em Debian e Ubuntu.

```bash
apt update
apt list --upgradable
apt full-upgrade -y
test -f /var/run/reboot-required && echo "reboot pendente"
```

Depois rode uma coleta e confira o resultado.

### Pacote corrigível que o gerenciador não atualiza

Se o trivy aponta uma CVE corrigível e o `apt` não tem atualização, o pacote provavelmente é órfão de uma versão anterior do sistema. Veja [sistemas-operacionais.md](sistemas-operacionais.md).

## Quando não há correção

CVEs sem patch publicado não se resolvem por comando. Há três caminhos.

1. Reduzir a superfície, removendo pacotes que o servidor não usa.
2. Aceitar o risco de forma documentada, com controle compensatório, como restringir a porta do serviço afetado.
3. Aguardar a correção do fornecedor. O indicador de idade da CVE corrigível mais antiga mede esse atraso depois que o patch existe.
