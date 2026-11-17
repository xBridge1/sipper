# Changelog

Todas as mudancas relevantes do SIPPER sao registradas neste arquivo.

## [1.3.0] - 2026-11-16

### Added

- Leitura de RTCP (Sender/Receiver Reports): perda e jitter medidos pelo receptor e RTT estimado, com os findings `rtcp_reported_loss`, `rtcp_reported_jitter` e `rtcp_high_rtt`.
- Novos diagnosticos SIP: retransmissoes sobre UDP (`sip_retransmission`), post-dial delay alto (`sip_slow_call_setup`) e IP privado no SDP enviado de IP publico (`sip_sdp_private_address`).
- Comparacao SDP x RTP: payload type nao negociado (`rtp_payload_not_negotiated`), ptime diferente do negociado (`rtp_ptime_mismatch`) e RTP vindo de origem diferente da anunciada (`rtp_source_mismatch`).
- MOS pelo E-model (ITU-T G.107) com Ie/Bpl por codec e atraso, usando o RTT do RTCP quando disponivel.
- Pagina RTP com MOS, jitter maximo e duracao por stream, valores coloridos por gravidade e grafico de jitter/perdas no tempo para o stream selecionado.
- Grafico de trafego com eixo secundario para protocolos de baixo volume e marcas de inicio/fim de chamada.
- Configuracao do percentual de perda RTP para severidade alta.

### Changed

- Descricoes, recomendacoes e evidencias dos findings exibidas em portugues na interface e nos relatorios.
- Perda RTP classificada por percentual (com minimo de pacotes perdidos), retransmissao TCP e pacotes fora de ordem por taxa, e nao mais por contagem absoluta.
- Jitter alto passa a usar o jitter RFC 3550 suavizado; o pico entre dois pacotes continua visivel como evidencia.
- Visao geral com oito indicadores, paineis de texto substituidos por grades de metricas, barra lateral compacta com secoes recolhiveis e icones monocromaticos que acompanham o tema.
- Itens duplicados removidos (status repetido, selo de pagina e filtros que ja existem na barra lateral).

### Fixed

- Comfort noise (CN) e DTMF (RFC 4733) eram reportados como troca de codec e anomalia de timestamp.
- Pausas por supressao de silencio (VAD) eram reportadas como interrupcao do stream e rebaixavam a qualidade da chamada para "Ruim".
- Fluxos UDP curtos cujo primeiro byte parece RTP eram tratados como midia, gerando "RTP sem SIP" e "audio em uma via" falsos.
- Reinicio de sequencia RTP era contado como milhares de pacotes perdidos ou como pacotes fora de ordem.
- Audio em uma via era apontado quando o retorno usava outra porta (RTP nao simetrico) ou quando o SDP negociou midia unidirecional.
- Numeros dos indicadores da visao geral apareciam pequenos porque o estilo global sobrescrevia a fonte.
- Linha selecionada ficava ilegivel no tema claro.

## [1.2.0] - 2026-11-15

### Added

- Leitor nativo de pcap e pcapng (`ciper/pcap_reader.py`) e decodificador leve de pacotes (`ciper/packets.py`) com suporte a Ethernet, VLAN/QinQ, PPPoE, MPLS, Linux SLL/SLL2, loopback, IPv4/IPv6 com cabecalhos de extensao e fragmentos.
- Barra de progresso real durante a analise, com etapa atual e percentual.
- Arrastar e soltar capturas na janela, analise automatica ao abrir um arquivo, lista de arquivos recentes e abertura pela linha de comando.
- Tela inicial com orientacao, atalhos de teclado (Ctrl+O, F5, Esc, Ctrl+E, Ctrl+F) e copia de linhas das tabelas (Ctrl+C).
- Nomes em portugues para todos os findings, severidades e estados de chamada na interface e nos relatorios (CSV ganhou a coluna `title`).
- Gerador de captura sintetica grande para benchmark (`tests/pcaps/generate_benchmark_pcap.py`).
- Testes para o leitor/decodificador, rotulos, preferencias e fluxo principal da janela (221 testes).

### Changed

- Analise cerca de 25x mais rapida: 65 MB / 285 mil pacotes passaram de 64 s para 2,5 s; pico de memoria de 1,5 GB para 300 MB.
- Cada pacote e decodificado uma unica vez; SIP, RTP e a classificacao de protocolo sao calculados uma vez e compartilhados entre o painel, o grafico e o engine.
- A remontagem TCP e feita uma unica vez e compartilhada entre SIP sobre TCP e TLS.
- scapy deixou de ser dependencia do aplicativo e passou para `requirements-dev.txt` (usado apenas nos testes), reduzindo o pacote instalado.
- Limite padrao de tamanho de captura aumentado de 1 GB para 4 GB.
- Interface dividida em modulos (`widgets`, `workers`, `styles`); o tema escolhido e lembrado entre sessoes.
- Eventos normais de chamada (estabelecida/encerrada) aparecem como "Info" e nao sao mais listados como falhas de sinalizacao.
- Horario de inicio das chamadas exibido como hora local (HH:MM:SS.mmm) em vez de timestamp Unix.

### Fixed

- Direcao de retransmissoes TCP em capturas Ethernet usava o endereco MAC em vez do IP.
- Padding Ethernet era contado como payload TCP, podendo gerar falsas retransmissoes.
- Leitura de records TLS e busca de SIP em fluxos TCP grandes tinham custo quadratico.
- Grafico "RTP OK" das estatisticas sempre mostrava zero.

## [1.1.0] - 2026-10-25

### Added

- Perfil opcional de compatibilidade FreeSWITCH, limitado aos IPs ou redes configurados pelo usuario.
- Diagnosticos para identidade anonymous, ofertas SDP unidirecionais, mod_callcenter, Request-URI, session timers, DTMF, enderecos de midia e headers SIP personalizados.
- Evidencias FreeSWITCH com Call-ID, Dialog-Key, caminho do pacote e referencias oficiais.
- Testes de regressao para atribuicao de falhas, correlacao temporal SIP/RTP, IPv6, configuracoes, atualizador, TLS e fragmentacao.

### Changed

- Correlacao SIP/RTP considera portas SDP e intervalo temporal da chamada para separar dialogos sequenciais que reutilizam o mesmo caminho de midia.
- Streams RTP no GUI sao associados por endpoints, portas e SSRC, evitando colisao entre chamadas.
- Findings SIP e ICMP apresentam a direcao real do pacote que contem o erro.
- Contagem de pacotes do dashboard usa o total efetivamente analisado, incluindo protocolos nao classificados.
- Evidencias de RTP apos BYE informam o atraso e toleram pacotes residuais de ate 100 ms.

### Fixed

- Falsos positivos de troca de payload type e SSRC entre chamadas RTP sequenciais.
- Falsos positivos de one-way audio entre pares de portas RTP diferentes e RTP orfao quando havia outro dialogo SIP na captura.
- Suporte IPv6 na classificacao geral, grafico de trafego e detectores TCP/UDP aplicaveis.
- Tratamento de SSL 3.0 como versao legada, records TLS Heartbeat validos e payloads malformados da API de atualizacao.
- Fragmentos IP duplicados deixaram de ser classificados como sobreposicao.
- Arquivos de configuracao invalidos ou com codificacao incorreta voltam aos valores seguros.
- Falha de permissao no diretorio do usuario nao impede a inicializacao do logging ou da interface.
- Thread de verificacao de atualizacao e liberada corretamente ao terminar.

### Validation

- Suite automatizada com 193 testes passando.
- Compilacao dos modulos, smoke test do GUI e analise de todas as amostras PCAP concluidas sem excecao.

## [1.0.4] - 2026-09-29

### Added

- Metricas de jitter RTP com suavizacao RFC 3550 e estimativa heuristica de MOS, indisponivel quando nao ha RTP.
- Metadados TLS: SNI, versoes e cipher suites ofertadas e negociadas, alem de mensagens de certificado observadas.
- Detector de cipher suites RC4/3DES e evidencias TLS no painel de seguranca.
- Deteccao de falhas REGISTER, REFER e OPTIONS sem resposta; resumo de re-INVITE, hold e resume.
- Gerador de PCAPs sinteticos para regressao de TCP, qualidade VoIP e TLS.
- SHA-256 do instalador, indicacao de checksum no atualizador e suporte opcional a assinatura Authenticode.

### Changed

- Resumo da chamada diferencia jitter suavizado de pico de variacao e apresenta operacoes SIP.
- Analise aceita geradores sem copia inicial e informa contadores de pacotes por protocolo.
- Atribuicao e evidencias de falhas SIP/TLS mais contextualizadas.

### Fixed

- Remontagem TCP para SIP/TLS, validacao SIP e tratamento de fluxos IPv6.
- Distincao estrutural de RTP/RTCP e correlacao SIP/RTP mais restrita.
- Identificacao de dialogos SIP e propagacao da selecao correta na interface.
- Remocao de implementacoes duplicadas e verificacao de erros nas etapas do build.

### Validation

- Suite automatizada com 140 testes passando.
- MOS e heuristico; certificados TLS criptografados e qualidade percebida nao sao validados pela captura.

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
