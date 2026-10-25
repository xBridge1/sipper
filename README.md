# SIPPER

> **SIP PCAP Insights** - analise offline de capturas PCAP para diagnostico de rede e VoIP.

[![Release](https://img.shields.io/github/v/release/xBridge1/sipper?label=release)](https://github.com/xBridge1/sipper/releases/latest)
[![Release Windows](https://github.com/xBridge1/sipper/actions/workflows/release-windows.yml/badge.svg)](https://github.com/xBridge1/sipper/actions/workflows/release-windows.yml)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB)
![Tests](https://img.shields.io/badge/tests-193%20passing-brightgreen)

![SIPPER](sipper/logo/splash.png)

O SIPPER transforma uma captura PCAP em uma visao operacional de problemas de rede, sinalizacao SIP e midia RTP. Ele identifica evidencias, aponta origem e destino, classifica severidade e apresenta recomendacoes para acelerar a investigacao de chamadas.

## Download

Versao atual: **SIPPER 1.1.0**.

- [Baixar o instalador para Windows](https://github.com/xBridge1/sipper/releases/download/v1.1.0/SIPPER-Setup-1.1.0.exe)
- [Baixar a versao portatil](https://github.com/xBridge1/sipper/releases/download/v1.1.0/SIPPER-portable-1.1.0.zip)
- [Verificar o checksum SHA-256](https://github.com/xBridge1/sipper/releases/download/v1.1.0/SIPPER-Setup-1.1.0.exe.sha256)
- [Consultar notas e arquivos do release](https://github.com/xBridge1/sipper/releases/tag/v1.1.0)

## Destaques

- Interface desktop moderna em PySide6 com temas claro e escuro.
- Analise local e offline de arquivos PCAP, sem enviar capturas para a internet.
- Painel de resumo com protocolos, severidade, chamadas, RTP e trafego ao longo do tempo.
- Fluxo visual SIP com direcao das mensagens e estados da chamada.
- Exportacao de resultados em JSON, CSV e PDF.
- Configuracoes persistentes para limites de jitter, perda, tamanho de captura e perfil da plataforma VoIP.
- Processamento em streaming para reduzir o uso de memoria em arquivos grandes.
- Cancelamento seguro de analises em andamento e log rotativo local.

## Protocolos e diagnosticos

### TCP, UDP e ICMP

- TCP flows, SYN failures, handshake incompleto ou lento, retransmissoes e resets.
- UDP flows, ausencia de resposta e bursts sem resposta.
- ICMP echo sem resposta, destination unreachable, time exceeded, redirect e parameter problem.
- Correlacao entre falhas UDP, ICMP e fluxos SIP/RTP quando houver evidencia compativel.

### SIP

- Correlacao por `Call-ID`, origem, destino, estados e duracao da chamada.
- Mensagens `INVITE`, respostas `1xx`, `2xx`, `ACK`, `BYE` e `CANCEL`.
- Erros SIP `4xx`, `5xx` e `6xx`, timeout de INVITE, `200 OK` sem ACK e falhas de `REGISTER`, `REFER` e `OPTIONS`.
- Eventos de re-INVITE, hold e resume no resumo operacional da chamada.
- Identificacao de sinalizacao fragmentada e cabecalhos SIP excessivamente grandes.
- Leitura de SDP para enderecos de midia, codecs, RTCP, `rtcp-mux` e `mid`.

### Compatibilidade FreeSWITCH

- Perfil opcional limitado aos IPs ou redes configurados pelo usuario.
- Riscos relacionados a ofertas SDP `sendonly`, `recvonly`, `inactive` e midia desativada.
- Analise de identidade anonymous, headers de identidade, Request-URI, session timers, DTMF e enderecos RTP.
- Alertas de compatibilidade para dialplan, `mod_sofia`, `mod_callcenter` e variaveis `sip_h_*`.

### RTP

- Streams por SSRC, endpoints, portas, codec estimado e duracao.
- Packet loss, jitter RFC 3550, MOS estimado, pacotes fora de ordem e anomalias de timestamp.
- Interrupcoes de stream, mudancas de payload type e SSRC.
- Provavel audio em uma via e correlacao entre qualidade de midia e chamada SIP.

### TLS e fragmentacao

- ClientHello, ServerHello, alertas fatais, versoes legadas, SNI e cipher suites.
- Deteccao de RC4, 3DES, records malformados e falhas de resposta TLS.
- Fragmentacao IPv4/IPv6 incompleta, sobreposta ou duplicada e riscos de MTU no SIP.

## Requisitos

- Windows 10 ou 11
- Python 3.12+
- Dependencias listadas em `requirements.txt`

## Desenvolvimento local

```powershell
git clone https://github.com/xBridge1/sipper.git SIPPER-repo
cd SIPPER-repo\sipper
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Como usar

### Interface grafica

```powershell
python -m ciper.gui_main
```

Na aplicacao, selecione um arquivo `.pcap` ou `.pcapng`, clique em **Analisar** e navegue pelas visoes de Resumo, SIP, RTP, Rede, Findings e Estatisticas. Use **Exportar** para gerar o relatorio da analise atual.

### Linha de comando

```powershell
python -m ciper.main
```

O modo de linha de comando permanece disponivel para uma consulta textual dos fluxos e findings. A interface grafica e a experiencia principal do produto.

## Testes

Execute toda a suite com o ambiente virtual ativo:

```powershell
python -m pytest
```

A versao 1.1.0 possui **193 testes automatizados** para TCP, UDP, ICMP, SIP, RTP, TLS, fragmentacao, FreeSWITCH, correlacoes, relatorios, configuracoes, atualizador e leitura de PCAP em streaming.

## Estrutura

```text
ciper/
  detectors/       Detectores por protocolo
  gui/             Interface PySide6, temas e view models
  engine.py        Orquestracao, correlacao e sumarios de chamadas
  sip.py            Parser e fluxos SIP/SDP
  rtp.py            Parser e streams RTP
  reporting.py      Exportacao JSON, CSV e PDF
  settings.py       Configuracoes persistentes da analise
samples/           Capturas de exemplo
tests/             Suite automatizada
logo/              Identidade visual da aplicacao
```

## Privacidade e limites

O SIPPER analisa os arquivos localmente. Capturas PCAP podem conter IPs, numeros, identificadores SIP e outras informacoes sensiveis; trate os arquivos e relatorios de acordo com a politica de seguranca da sua organizacao.

As conclusoes sao baseadas no que foi efetivamente capturado. Ausencia de trafego em uma captura nao prova, por si so, que ele nao existiu na rede. Para diagnosticos de voz mais confiaveis, capture ambos os sentidos da sinalizacao e da midia RTP.

## Proximos passos

- Assinatura Authenticode do instalador para distribuicao corporativa.
- Ampliacao da cobertura de PCAPs reais anonimizados e testes de regressao.
- Correlacao SIP/SDP/RTP para cenarios com SBC, NAT, ICE e multiplas midias.
- Perfis opcionais para outras plataformas VoIP, mantendo o FreeSWITCH como primeira implementacao.
