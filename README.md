# Sec-INE5429-TG
Desenvolvimento do trabalho em Grupo final para a disciplina de Segurança em Computação.

## Instruções de Uso:

```bash
pip install -r requirements.txt
python benchmark.py --quick        # 20 iterações (rápido)
python benchmark.py -n 100         # 100 iterações (padrão)
python benchmark.py --csv out.csv  # exporta para CSV
```

## Estrutura do benchmark.py

5 blocos funcionais, seguindo fielmente o pseudocódigo do relatório:

- `SchemeBase` + 3 wrappers — interface uniforme _keygen / sign / verify / pk_to_bytes / sk_to_bytes_.
  - `ECDSAWrapper` encapsula a API orientada a objetos da cryptography;
  - `DilithiumWrapper` (e sua subclasse `DilithiumInstrumented`) envolve a API funcional de _dilithium-py_.
- `DilithiumInstrumented` — subclasse que espelha o loop _while True_ do _sign()_ do dilithium-py (inspecionado em tempo de execução) com um contador attempt embutido,
  - medindo a média de tentativas e a taxa de sinais que sofreram pelo menos uma rejeição.
- `sanity_check()` — antes do benchmark, valida 3 invariantes por esquema: aceita assinatura válida, rejeita mensagem alterada, rejeita assinatura corrompida.
- `run_benchmark()` — implementação direta do pseudocódigo do relatório, com barra de progresso por fase.
- `print_results()` — tabela com média ± desvio padrão e tabela de razões (Dilithium / ECDSA).