# Corpus de regressao

Cada captura deste diretorio tem um `.expected.json` com o veredito que o
SIPPER deve continuar dando. `tests/test_corpus.py` falha se uma mudanca
alterar esse veredito, o que protege a confiabilidade do "provavel culpado".

- `synthetic/`: cenarios construidos com veredito conhecido. Gere de novo com
  `python -m tests.corpus.generate_corpus`.
- `samples/`: expectativas para as capturas em `samples/` (campo `pcap`).
- `real/`: capturas reais adicionadas pela equipe.

## Adicionar uma captura real

1. Abra a captura no SIPPER e confirme que o veredito esta correto.
2. Grave a expectativa:

   ```
   python -m tests.corpus.record caminho/captura.pcap --freeswitch 10.0.0.20
   ```

3. Revise o `.expected.json` gerado: remova chaves que nao importam para o
   caso e adicione `absent_findings` para falsos positivos que nao podem voltar.

Nao versione capturas com dados de clientes sem autorizacao; anonimize IPs e
numeros antes (por exemplo com `tcprewrite`/`TraceWrangler`).

## Formato

```json
{
  "pcap": "../../samples/exemplo.pcap",
  "settings": {"target_platform": "freeswitch", "target_platform_ips": "10.0.0.20"},
  "diagnosis": {"status": "fail", "root_type": "sip_error_response", "culprit_ip": "10.0.0.30"},
  "calls": {"call-id-1": {"status": "user"}},
  "present_findings": ["sip_error_response"],
  "absent_findings": ["rtp_one_way_audio"]
}
```

Apenas as chaves presentes sao comparadas.
