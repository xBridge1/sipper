# SIPPER

> **SIP PCAP Insights** - analise offline de capturas PCAP para diagnostico de rede e VoIP.

![SIPPER](logo/splash.png)

O SIPPER transforma uma captura PCAP em uma visao operacional de problemas de rede, sinalizacao SIP e midia RTP. Ele identifica evidencias, aponta origem e destino, classifica severidade e apresenta recomendacoes para acelerar a investigacao de chamadas.

## Destaques

- Interface desktop moderna em PySide6 com temas claro e escuro.
- Analise local e offline de arquivos PCAP, sem enviar capturas para a internet.
- Painel de resumo com protocolos, severidade, chamadas, RTP e trafego ao longo do tempo.
- Fluxo visual SIP com direcao das mensagens e estados da chamada.
- Exportacao de resultados em JSON, CSV e PDF.
- Configuracoes persistentes para limites de jitter, perda e tamanho de captura.
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
- Erros SIP `4xx`, `5xx` e `6xx`, timeout de INVITE e `200 OK` sem ACK.
- Identificacao de sinalizacao fragmentada e cabecalhos SIP excessivamente grandes.
- Leitura de SDP para enderecos de midia, codecs, RTCP, `rtcp-mux` e `mid`.

### RTP

- Streams por SSRC, endpoints, portas, codec estimado e duracao.
- Packet loss, jitter elevado, pacotes fora de ordem e anomalias de timestamp.
- Interrupcoes de stream, mudancas de payload type e SSRC.
- Provavel audio em uma via e correlacao entre qualidade de midia e chamada SIP.

## Requisitos

- Windows 10 ou 11
- Python 3.12+
- Dependencias listadas em `requirements.txt`

## Instalacao

```powershell
git clone <url-do-repositorio>
cd sipper
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

Os testes cobrem deteccoes TCP, UDP, ICMP, SIP e RTP, correlacoes do engine, relatorios, configuracoes, cancelamento e leitura de PCAP em streaming.

## Instalador Windows

O projeto inclui uma cadeia de distribuicao para Windows com PyInstaller e Inno Setup. O resultado e um instalador padrao com escolha da pasta de destino, atalho opcional na area de trabalho, entrada no menu Iniciar e desinstalador pelo Windows.

1. Instale o [Inno Setup](https://jrsoftware.org/isinfo.php) no Windows.
2. Ative o ambiente virtual e execute:

```powershell
.\packaging\build.ps1 -Version 1.0.2
```

O executavel de teste sera criado em `dist\SIPPER\SIPPER.exe` e o instalador final em `dist-installer\SIPPER-Setup-1.0.2.exe`.

Para montar apenas o executavel, sem exigir o Inno Setup:

```powershell
.\packaging\build.ps1 -SkipInstaller
```

### Publicacao no GitHub Releases

Depois de enviar o commit para o GitHub, uma tag com prefixo `v` gera automaticamente a release Windows. O workflow executa os testes, cria o instalador e publica dois arquivos: o instalador `SIPPER-Setup-<versao>.exe` e a versao portatil `.zip`.

```powershell
git tag v1.0.2
git push origin v1.0.2
```

O acompanhamento fica na aba **Actions** do repositorio. Quando o workflow terminar, os arquivos estarao na aba **Releases**.

## Atualizacoes

Ao iniciar, o SIPPER verifica em segundo plano a release mais recente publicada no GitHub. A tela **Sobre** mostra a versao instalada e disponibiliza um botao para verificar atualizacoes manualmente. Quando houver uma nova versao, o botao abre o instalador oficial da release para que o Windows atualize o programa com seguranca.

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
packaging/          Scripts para EXE e instalador Windows
```

## Privacidade e limites

O SIPPER analisa os arquivos localmente. Capturas PCAP podem conter IPs, numeros, identificadores SIP e outras informacoes sensiveis; trate os arquivos e relatorios de acordo com a politica de seguranca da sua organizacao.

As conclusoes sao baseadas no que foi efetivamente capturado. Ausencia de trafego em uma captura nao prova, por si so, que ele nao existiu na rede. Para diagnosticos de voz mais confiaveis, capture ambos os sentidos da sinalizacao e da midia RTP.

## Proximos passos

- Empacotamento do aplicativo como EXE para distribuicao no Windows.
- Evolucao de correlacao SIP/SDP/RTP para cenarios mais complexos.
- Ampliacao da cobertura de PCAPs reais e testes de regressao.
