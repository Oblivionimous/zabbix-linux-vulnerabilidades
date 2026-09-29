# Roadmap

Lista de melhorias identificadas, em ordem de prioridade sugerida.

## Alta

### Versão do script dentro do relatório

Gravar no `report.json` um identificador de versão ou hash curto do script e expor como item do template. Um dashboard de frota mostraria qual host ficou com cópia antiga, sem acesso por SSH.

### Idade da base de vulnerabilidades do trivy

O relatório pode sair `ok` com a base desatualizada, e o trivy deixa de ver CVEs novas. Capturar a data de `/var/cache/trivy/db/metadata.json`, expor como item e criar uma trigger para bases com mais de alguns dias.

### Notificação por ação do Zabbix

O template cria triggers mas nenhuma ação. Criar ações por tag `scope: security` com envio por email ou webhook.

## Média

### Escalonar alertas por idade

Hoje as triggers de CVE HIGH disparam com qualquer valor acima do limite. Combinar a contagem com o item `vuln.trivy.oldest_days` reduz ruído entre janelas de patch.

### Host consolidado da frota

Criar um host sem interface com itens calculados, por exemplo `sum(last_foreach(/*/vuln.trivy.fixable[CRITICAL]?[group="Linux servers"]))`, para ter um número único de frota e histórico próprio.

### Distribuição por Ansible

Um playbook que executa o instalador, copia `extra-skip-dirs` por grupo de hosts e confere o hash. Necessário para além de poucos hosts.

### Relatório agendado em PDF

Usar os relatórios agendados do Zabbix para enviar semanalmente o dashboard de vulnerabilidades.

### Gráfico de barras no Grafana

Ranking horizontal de pacotes com `volkovlabs-echarts-panel`, depois de validar a sintaxe de consulta e de opções do painel. Validar também as tabelas Business Text em uma instância real.

## Baixa

### Reservar espaço para corrigíveis em top_cves

Garantir que CVEs corrigíveis de severidade menor entrem no ranking mesmo quando há muitas CVEs críticas sem correção.

### Aviso de datetime.utcnow

Trocar por `datetime.now(datetime.timezone.utc)` em uma nova versão do script. A troca muda o hash e exige redistribuição.

### Espelho interno da base do trivy

Para hosts sem saída à internet, hospedar a base em um registro interno e usar a opção `--db-repository`.

### Cartões de valor único no dashboard

Adicionar widgets Item value para CVEs CRITICAL corrigíveis, status da coleta e reboot pendente.

### Testes em contêineres

Executar o coletor em imagens Rocky, Debian e Ubuntu no workflow de CI, para detectar diferenças de comportamento entre distribuições.

### Redução de superfície

Levantar pacotes instalados e não usados nos hosts para reduzir CVEs sem correção.
