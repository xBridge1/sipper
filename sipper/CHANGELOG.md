# Changelog

Todas as mudancas relevantes do SIPPER sao registradas neste arquivo.

## [1.5.0] - 2026-11-26

### Added

- Perfil FreeSWITCH: novo finding `freeswitch_callcenter_midcall_hold` para re-INVITE da operadora que coloca a chamada em espera no meio da ligacao (`a=sendonly`, `a=inactive`, `a=recvonly`, porta 0 ou `c=0.0.0.0`). No `mod_callcenter` esse hold ja causou chamadas cruzadas; a evidencia traz o CSeq, o tipo de hold, a resposta do FreeSWITCH, a duracao e se a chamada terminou ainda em espera. Hold feito pelo proprio FreeSWITCH, hold recusado e chamada que ja comeca em espera nao geram o alerta.

### Fixed

- Desafio de autenticacao `401`/`407` seguido de nova tentativa com credenciais era alarmado como chamada recusada e contado como uma chamada a mais. O desafio agora fica no mesmo fluxo da chamada e e tratado como negociacao; `401`/`407` repetido apos enviar credenciais (senha errada) ou sem nova tentativa continua sendo falha.
- A nova tentativa autenticada apos `401`/`407` era contada como re-INVITE.
- `491 Request Pending` em re-INVITE de chamada ja estabelecida (glare) era alarmado como recusa; agora e tratado como negociacao.
- Re-INVITE de hold ou retomada recusado (`491`, `488`...) era contado como hold/retomada e podia justificar indevidamente gaps de RTP.
- Transacoes INVITE eram identificadas so pelo numero do CSeq; um re-INVITE de cada lado com o mesmo numero fazia um deles ser tratado como retransmissao.

## [1.4.0] - 2026-11-25

### Added

- Veredito com **provavel culpado**: cada chamada e a captura inteira recebem status (Falha, Degradada, Risco, Resultado normal, OK), manchete objetiva, host/papel responsavel, nivel de confianca, raciocinio passo a passo e proximos passos. A causa raiz e separada dos sintomas (ex.: header rejeitado com 400 explica a chamada recusada).
- Base de conhecimento de codigos SIP (`ciper/sip_status.py`): significado, lado culpado (origem, destino, negociacao, proximo salto ou resultado normal), acao recomendada e hangup cause equivalente do FreeSWITCH.
- Detector de higiene de mensagens SIP (`ciper/detectors/sip_headers.py`) com a linha exata do problema e confirmacao quando o destino responde 400/415/420/483/488: caracteres de controle, bytes nao UTF-8 (Latin-1) em From/identidade, headers singleton duplicados, headers obrigatorios ausentes, Contact ausente, CSeq divergente, Max-Forwards esgotado, sintaxe `${...}` (expansao de variaveis do FreeSWITCH), From/To/Contact malformados, Request-URI invalida (espaco, `#` sem escape), `Require` nao suportado pelo FreeSWITCH, Content-Encoding, corpo sem Content-Type, SIP/TCP sem Content-Length, quebras LF sem CR, folding, nomes de header invalidos, From sem tag, versao SIP invalida, SDP incompleto, payload dinamico sem rtpmap e oferta SRTP/DTLS.
- Interface: cartao de veredito no topo da Visao geral e do Diagnostico (raciocinio recolhivel), coluna "Provavel culpado" e marcacao "Causa raiz" na fila de incidentes, detalhe do incidente com a linha do header problematico e veredito no detalhe da chamada.
- Relatorios JSON, CSV e PDF com o veredito, o provavel culpado e a confianca.
- Causa Q.850 do header `Reason` usada para refinar o culpado das recusas e novo finding `sip_abnormal_hangup` para BYE com causa anormal; o resumo da chamada mostra quem desligou.
- Ponto de captura configuravel ou detectado automaticamente, refinando o culpado de INVITE sem resposta, 200 OK sem ACK, audio em uma via e degradacao de midia.
- Correlacao das pernas A/B do FreeSWITCH (B2BUA): a falha da perna B e propagada para o veredito da perna A e a chamada e contada uma vez.
- Audio mudo (`rtp_silent_audio`): RTP G.711 com silencio digital.
- Digitos DTMF (RFC 4733 e SIP INFO) no resumo da chamada.
- Comparacao oferta x resposta SDP: codec nao ofertado, sem codec comum, DTMF removido ou com payload diferente, direcao invalida e linhas `m=` divergentes.
- `Contact` com IP privado (NAT), REGISTER com credenciais recusadas, registro longo demais atras de NAT e aviso de SIP sobre TLS.
- Perfil FreeSWITCH com codecs aceitos, `enable-100rel`, `enable-timer` e SRTP para prever `488`/`420`; listas de headers `X-` ignorados e peers confiaveis.
- SIP Flow abre na mensagem culpada, destacada no ladder e no texto bruto; botoes para copiar o resumo da captura ou da chamada; filtro de causas raiz.
- Linha de comando reescrita: varios arquivos, `--json`, `--ticket`, `--freeswitch`, `--capture-point` e `--fail-on` para automacao.
- Corpus de regressao de vereditos (`tests/corpus/`) com gravador para capturas reais, e fuzzing dos parsers com Hypothesis.

### Changed

- Respostas 480/486/487/600/603 passam a ser tratadas como resultado normal da chamada (severidade baixa), nao como falha tecnica.
- O titulo de recusas SIP mostra o codigo e o significado (ex.: "Recusa SIP 488 (Midia nao aceitavel)").
- `ciper/gui/app.py` dividido em modulos (renderizacao, tabelas, configuracoes, diagnostico).
- INVITE sem resposta em captura mais curta que o Timer B (32 s) recebe severidade e confianca menores.
- Audio em uma via aponta o sentido sem RTP; perda e jitter apontam o sentido do caminho degradado; ICMP aponta quem emitiu o erro (porta fechada, roteador, firewall).

### Fixed

- Mensagens SIP com bytes nao UTF-8 eram descartadas silenciosamente e nao apareciam na analise.
- Requisicoes com espaco na Request-URI eram descartadas silenciosamente.
- Headers repetidos (Via, Record-Route, duplicatas) perdiam todas as copias exceto a ultima; o branch passa a vir do Via do topo.
- Um byte Latin-1 em campos numericos (CSeq, Content-Length, portas do SDP) derrubava o parser SIP (encontrado pelo fuzzing).
- Requisicoes enviadas pelo lado chamado (ex.: BYE do destino) eram desenhadas na direcao errada no SIP Flow.
- Checkbox desmarcado era invisivel no tema escuro.

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
