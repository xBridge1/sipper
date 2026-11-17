# SIPPER

> **SIP PCAP Insights** - analise offline de capturas PCAP para diagnostico de rede e VoIP.

[![Release](https://img.shields.io/github/v/release/xBridge1/sipper?label=release)](https://github.com/xBridge1/sipper/releases/latest)
[![Release Windows](https://github.com/xBridge1/sipper/actions/workflows/release-windows.yml/badge.svg)](https://github.com/xBridge1/sipper/actions/workflows/release-windows.yml)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB)
![Tests](https://img.shields.io/badge/tests-244%20passing-brightgreen)

![SIPPER](logo/splash.png)

O SIPPER transforma uma captura PCAP em uma visao operacional de problemas de rede, sinalizacao SIP e midia RTP. Ele identifica evidencias, aponta origem e destino, classifica severidade e apresenta recomendacoes para acelerar a investigacao de chamadas.

## Download

Versao atual: **SIPPER 1.3.0**.

- [Baixar o instalador para Windows](https://github.com/xBridge1/sipper/releases/download/v1.3.0/SIPPER-Setup-1.3.0.exe)
- [Baixar a versao portatil](https://github.com/xBridge1/sipper/releases/download/v1.3.0/SIPPER-portable-1.3.0.zip)
- [Verificar o checksum SHA-256](https://github.com/xBridge1/sipper/releases/download/v1.3.0/SIPPER-Setup-1.3.0.exe.sha256)
- [Consultar notas e arquivos do release](https://github.com/xBridge1/sipper/releases/tag/v1.3.0)

## Destaques

- Interface desktop moderna em PySide6 com temas claro e escuro (o tema escolhido e lembrado).
- Arraste um `.pcap`/`.pcapng` para a janela ou abra um recente: a analise comeca sozinha, com barra de progresso real.
- Leitor nativo de pcap/pcapng: analise cerca de 25x mais rapida e com 5x menos memoria que a versao 1.1.0.
- Findings com nomes claros em portugues (ex.: "Jitter alto no RTP"), mantendo o codigo tecnico para busca.
- Analise local e offline de arquivos PCAP, sem enviar capturas para a internet.
- Painel de resumo com protocolos, severidade, chamadas, RTP e trafego ao longo do tempo.
- Fluxo visual SIP com direcao das mensagens e estados da chamada.
- Exportacao de resultados em JSON, CSV e PDF.
- Configuracoes persistentes para limites de jitter, perda, tamanho de captura e perfil da plataforma VoIP.
- Processamento em streaming: cada pacote e decodificado uma unica vez em um registro compacto.
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
- Erros SIP `4xx`, `5xx` e `6xx`, timeout de INVITE, `200 OK` sem ACK, falhas de `REGISTER`, `REFER` e `OPTIONS`.
- Eventos de re-INVITE, hold e resume no resumo operacional da chamada.
- Identificacao de sinalizacao fragmentada e cabecalhos SIP excessivamente grandes.
- Retransmissoes SIP sobre UDP, post-dial delay alto e IP privado no SDP (NAT).
- Leitura de SDP para enderecos de midia, codecs, RTCP, `rtcp-mux` e `mid`.

### Compatibilidade FreeSWITCH

- Perfil opcional ativado em **Configuracoes**, com filtro por IP ou rede do servidor monitorado.
- Risco de oferta inicial `sendonly`, `recvonly`, `inactive` ou com porta de audio desativada.
- Identidade `anonymous` correlacionada com `P-Asserted-Identity`, `P-Preferred-Identity`, `Remote-Party-ID` e `Privacy` sem equiparar identidade preferida a identidade afirmada.
- Mapeamento de Request-URI para `destination_number` e de `To` para `sip_to_user`, com alerta de reescrita divergente por operadora ou SBC.
- Validacao de `Session-Expires` e `Min-SE`, negociacao DTMF por `telephone-event` ou SIP `INFO` e endereco RTP usado em `remote_media_ip`.
- Headers personalizados `X-*` apresentados como entradas `sip_h_*` que podem influenciar dialplan e legs encaminhados.
- Risco combinado para chamadas interativas e `mod_callcenter`, sem tratar hold por re-INVITE como falha.

### RTP

- Streams por SSRC, endpoints, portas, codec estimado e duracao.
- Packet loss por percentual, jitter RFC 3550, picos de variacao entre pacotes, pacotes fora de ordem e anomalias de timestamp.
- MOS pelo E-model (ITU-T G.107) considerando codec, perda, jitter e RTT.
- Comfort noise, DTMF (RFC 4733) e supressao de silencio reconhecidos, sem gerar alertas falsos.
- Interrupcoes de stream, mudancas de payload type e SSRC, e reinicio de sequencia.
- Provavel audio em uma via e correlacao entre qualidade de midia e chamada SIP.
- RTCP Sender/Receiver Reports: perda e jitter vistos pelo receptor e RTT estimado.
- Comparacao com o SDP: payload type nao negociado, ptime divergente e RTP de origem diferente da anunciada (NAT).

### TLS e fragmentacao

- ClientHello, ServerHello, alertas fatais, versoes TLS legadas e registros malformados.
- SNI, versoes e cipher suites ofertadas, versao e cipher suite negociadas quando observaveis.
- Deteccao de oferta ou negociacao de RC4 e 3DES, com evidencias do handshake correspondente.
- Fragmentacao IP incompleta, sobreposta e correlacao com sinalizacao SIP e risco de MTU.

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
python -m pip install -r requirements-dev.txt
```

`requirements.txt` contem apenas as dependencias do aplicativo (PySide6 e packaging). `requirements-dev.txt` acrescenta pytest e scapy, usados somente pela suite de testes.

## Como usar

### Interface grafica

```powershell
python -m ciper.gui_main
```

Arraste um arquivo `.pcap`, `.pcapng` ou `.cap` para a janela, clique em **Abrir PCAP** ou escolha um item em **Recentes**: a analise comeca automaticamente. Depois navegue pelas visoes de Resumo, Diagnostico, SIP, RTP, Rede, Findings e Estatisticas. Para verificacoes especificas, selecione **FreeSWITCH** e informe os IPs monitorados em **Configuracoes** antes da analise. Use **Exportar** para gerar o relatorio da analise atual.

Tambem e possivel abrir uma captura direto pela linha de comando: `python -m ciper.gui_main captura.pcap` (ou `SIPPER.exe captura.pcap`).

| Atalho | Acao |
| --- | --- |
| `Ctrl+O` | Abrir e analisar uma captura |
| `F5` | Analisar novamente o arquivo atual |
| `Esc` | Cancelar a analise em andamento |
| `Ctrl+E` | Exportar relatorio |
| `Ctrl+F` | Buscar na pagina atual |
| `Ctrl+C` | Copiar as linhas selecionadas de uma tabela |

### Linha de comando

```powershell
python -m ciper.main captura.pcap
```

O modo de linha de comando permanece disponivel para uma consulta textual dos fluxos e findings. A interface grafica e a experiencia principal do produto.

## Testes

Execute toda a suite com o ambiente virtual ativo:

```powershell
python -m pytest
```

A suite possui **221 testes automatizados**. Eles cobrem deteccoes TCP, UDP, ICMP, SIP, RTP, TLS, fragmentacao e FreeSWITCH, alem de correlacoes do engine, relatorios, configuracoes, atualizador, cancelamento, leitura de pcap/pcapng e o fluxo principal da interface. O corpus sintetico reproduzivel esta em `tests/pcaps/`.

Para medir desempenho, gere uma captura sintetica grande e analise-a:

```powershell
python tests/pcaps/generate_benchmark_pcap.py bench.pcap --calls 100 --seconds 30
python -m ciper.main bench.pcap
```

## Instalador Windows

O projeto inclui uma cadeia de distribuicao para Windows com PyInstaller e Inno Setup. O resultado e um instalador padrao com escolha da pasta de destino, atalho opcional na area de trabalho, entrada no menu Iniciar e desinstalador pelo Windows.

1. Instale o [Inno Setup](https://jrsoftware.org/isinfo.php) no Windows.
2. Ative o ambiente virtual e execute:

```powershell
.\packaging\build.ps1 -Version 1.3.0
```

O executavel de teste sera criado em `dist\SIPPER\SIPPER.exe`, o instalador final em `dist-installer\SIPPER-Setup-1.3.0.exe` e seu checksum em `dist-installer\SIPPER-Setup-1.3.0.exe.sha256`.

Para montar apenas o executavel, sem exigir o Inno Setup:

```powershell
.\packaging\build.ps1 -SkipInstaller
```

### Publicacao no GitHub Releases

Depois de enviar o commit para o GitHub, uma tag com prefixo `v` gera automaticamente a release Windows. O workflow na raiz do repositorio (`.github/workflows/release-windows.yml`) executa os testes e publica o instalador `SIPPER-Setup-<versao>.exe`, seu checksum `.exe.sha256` e o pacote portatil `.zip`.

```powershell
git tag v1.3.0
git push origin v1.3.0
```

O acompanhamento fica na aba **Actions** do repositorio. Quando o workflow terminar, os arquivos estarao na aba **Releases**.

Para assinatura Authenticode em uma maquina de release, defina `SIPPER_SIGN_CERTIFICATE` com o caminho de um certificado PFX. `SIPPER_SIGN_PASSWORD` e `SIPPER_TIMESTAMP_URL` sao opcionais. Sem essas variaveis, o build continua criando instalador e checksum, mas sem assinatura de codigo.

## Atualizacoes

Ao iniciar, o SIPPER verifica em segundo plano a release mais recente publicada no GitHub. A tela **Sobre** mostra a versao instalada e disponibiliza um botao para verificar atualizacoes manualmente. Quando houver uma nova versao, o botao abre o instalador oficial da release para que o Windows atualize o programa com seguranca.

## Estrutura

```text
ciper/
  detectors/       Detectores por protocolo
  gui/             Interface PySide6: app (janela), widgets, workers, styles, temas e view models
  packets.py       Decodificacao rapida de pacotes (Ethernet, VLAN, SLL, IPv4/IPv6, TCP/UDP/ICMP)
  pcap_reader.py   Leitor nativo de pcap e pcapng
  labels.py        Nomes em portugues de findings, severidades e estados
  engine.py        Orquestracao, correlacao e sumarios de chamadas
  sip.py            Parser e fluxos SIP/SDP
  rtp.py            Parser e streams RTP
  reporting.py      Exportacao JSON, CSV e PDF
  settings.py       Configuracoes persistentes da analise
samples/           Capturas de exemplo
tests/             Suite automatizada
logo/              Identidade visual da aplicacao
docs/              Mockup de referencia do painel
packaging/          Scripts para EXE e instalador Windows
```

## Privacidade e limites

O SIPPER analisa os arquivos localmente. Capturas PCAP podem conter IPs, numeros, identificadores SIP e outras informacoes sensiveis; trate os arquivos e relatorios de acordo com a politica de seguranca da sua organizacao.

As conclusoes sao baseadas no que foi efetivamente capturado. Ausencia de trafego em uma captura nao prova, por si so, que ele nao existiu na rede. Para diagnosticos de voz mais confiaveis, capture ambos os sentidos da sinalizacao e da midia RTP.

## Proximos passos

- Assinatura Authenticode do instalador para distribuicao corporativa.
- Ampliacao da cobertura de PCAPs reais anonimizados e testes de regressao.
- Correlacao SIP/SDP/RTP para cenarios com SBC, NAT, ICE e multiplas midias.
- Perfis opcionais para outras plataformas VoIP, mantendo o FreeSWITCH como primeira implementacao.
