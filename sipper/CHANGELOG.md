# Changelog

Todas as mudancas relevantes do SIPPER sao registradas neste arquivo.

## [1.0.3] - 2026-09-24

### Added

- SIP Flow permite selecionar uma mensagem pela seta ou lista e visualizar seu cabecalho SIP original.
- Findings exibem contexto tecnico correlacionado, incluindo sinalizacao SIP, SDP, streams RTP, SSRC, sequencias e picos de jitter.
- Referencias tecnicas por finding, com RFCs e fonte operacional de QoS explicando a aplicacao de cada referencia.
- Interpretacao de qualidade VoIP para perda e jitter, com faixas de alvo, atencao, degradacao e criticidade.

### Changed

- O diagnostico de jitter prioriza impacto, motivo do risco, fluxo afetado e pior pico observado em vez de listar todos os streams da chamada.
- A evidencia RTP agora e filtrada pelo SSRC e direcao que dispararam o finding.

### Fixed

- Pacotes RTCP nao sao mais classificados como streams RTP, evitando evidencias e fluxos de midia incorretos.

## [1.0.2] - 2026-09-23

### Added

- Deteccao de problemas TLS: alerta fatal, ClientHello sem resposta, versao legada e registro malformado.
- Analise de conjuntos de fragmentos IPv4 e IPv6, incluindo fragmentos incompletos e sobrepostos.
- Validacao de cabecalhos SIP e de `Content-Length`.
- Deteccao de risco de fragmentacao para mensagens SIP transportadas por UDP acima de 1200 bytes.
- Correlacao de fragmentos IP com o dialogo SIP por endereco, protocolo e portas quando disponiveis.
- Exibicao dos codecs RTP identificados por stream.

### Changed

- A navegacao da interface foi reorganizada por diagnostico, chamadas, midia, rede e seguranca.
- Findings agora mostram categoria, origem provavel, nivel de confianca, evidencias e proxima acao.
- Telas de SIP, RTP, rede e seguranca apresentam informacoes adaptadas ao tipo de incidente.
- O parser SIP registra mensagens reconstituídas a partir de segmentos TCP como evidencia tecnica, sem gerar falso positivo.

### Fixed

- A associacao de fragmentos a fluxos SIP deixou de depender apenas dos enderecos IP, reduzindo correlacoes indevidas em capturas concorrentes.
- Controles internos de filtro nao ficam mais visiveis indevidamente no canto superior da janela.

## [1.0.1] - 2026-09-12

### Added

- Teste que garante uma unica leitura fisica do arquivo PCAP durante a analise do engine.

### Changed

- A analise de TCP, UDP, ICMP, SIP e RTP passou a compartilhar uma unica passagem pela captura.
- O dashboard e o grafico de trafego usam os dados coletados durante essa mesma passagem.
- A versao usada pelo atualizador e inserida no aplicativo durante o empacotamento.
- O empacotamento deixa de incluir indiscriminadamente todos os modulos do PySide6.
- Tabelas e navegacao da interface foram ajustadas para comportamento responsivo em diferentes resolucoes.

### Fixed

- O fechamento da janela agora coordena corretamente analises em andamento e verificacoes de atualizacao.

## [1.0.0] - 2026-09-10

### Added

- Primeira release do SIPPER para Windows.
- Analise offline de rede, SIP e RTP com interface grafica e instalador.
