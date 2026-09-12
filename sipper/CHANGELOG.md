# Changelog

Todas as mudancas relevantes do SIPPER sao registradas neste arquivo.

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
