# Corpus de Regressao PCAP

Os PCAPs deste diretorio sao capturas sinteticas deterministicas para validar cenarios conhecidos sem dados de clientes.

Execute `python tests/pcaps/generate_pcaps.py` para gerar os arquivos locais:

- `tcp_retransmission.pcap`: handshake TCP seguido de retransmissao.
- `voip_quality.pcap`: chamada SIP com RTP, perda e pico de variacao entre pacotes.
- `tls_weak_cipher.pcap`: ClientHello com RC4 oferecido para validar o detector TLS.

Para testes de desempenho, `python tests/pcaps/generate_benchmark_pcap.py SAIDA.pcap --calls 100 --seconds 30` gera uma captura grande (cerca de 285 mil pacotes e 65 MB) com chamadas SIP, RTP bidirecional com perdas, falhas de chamada, TCP e ICMP. O arquivo nao e versionado.

Capturas reais devem ser anonimizadas, revisadas para remover credenciais e adicionadas apenas quando houver autorizacao para distribui-las. Cada nova captura deve ter um teste de regressao que registre os findings e resumos esperados.
