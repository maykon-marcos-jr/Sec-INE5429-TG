#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Experimento: Assinaturas Digitais Pós-Quânticas vs. Clássicas             ║
║  Esquemas  :  ECDSA P-256  ×  Dilithium2 (ML-DSA-44)  ×  Dilithium3       ║
║  Referência:  NIST FIPS 186-5 (ECDSA) e FIPS 204 (ML-DSA)                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Uso:                                                                        ║
║    pip install dilithium-py cryptography                                    ║
║    python benchmark.py                    # 100 iterações (padrão)          ║
║    python benchmark.py --quick            # 20  iterações (teste rápido)    ║
║    python benchmark.py -n 500             # N iterações personalizadas      ║
║    python benchmark.py --csv saida.csv    # exportar resultados em CSV      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
#  Verificação de dependências
# ══════════════════════════════════════════════════════════════════════════════

def _check_imports() -> None:
    """Aborta com mensagem de ajuda se alguma biblioteca faltar."""
    missing = []

    try:
        global ec, hashes, Encoding, PublicFormat, PrivateFormat, NoEncryption
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption,
        )
    except ImportError:
        missing.append("cryptography")

    try:
        global Dilithium2, Dilithium3
        from dilithium_py.dilithium import Dilithium2, Dilithium3
    except ImportError:
        missing.append("dilithium-py")

    if missing:
        pkgs = " ".join(missing)
        sys.exit(
            f"\n[ERRO] Dependência(s) ausente(s): {pkgs}\n"
            f"  Instale com:  pip install {pkgs}\n"
        )


_check_imports()


# ══════════════════════════════════════════════════════════════════════════════
#  Configuração global
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_N = 100                     # iterações padrão por operação

# Mensagem de teste reproduzível (~256 bytes)
TEST_MSG: bytes = (
    b"Mensagem de teste para benchmark de assinaturas digitais. "
    b"Comparacao: CRYSTALS-Dilithium (ML-DSA / FIPS 204) "
    b"vs ECDSA P-256 (FIPS 186-5). Relatorio parcial 2026. "
    b"[padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]"
)
assert len(TEST_MSG) >= 200, "Mensagem de teste muito curta"


# ══════════════════════════════════════════════════════════════════════════════
#  Wrappers — interface uniforme para todos os esquemas
# ══════════════════════════════════════════════════════════════════════════════

class SchemeBase:
    """Interface comum para todos os esquemas de assinatura."""
    name: str = "Desconhecido"

    def keygen(self) -> tuple[Any, Any]:
        """Retorna (chave_publica, chave_privada)."""
        raise NotImplementedError

    def sign(self, sk: Any, msg: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, pk: Any, msg: bytes, sig: bytes) -> bool:
        raise NotImplementedError

    def pk_to_bytes(self, pk: Any) -> bytes:
        raise NotImplementedError

    def sk_to_bytes(self, sk: Any) -> bytes:
        raise NotImplementedError


# ── ECDSA P-256 ───────────────────────────────────────────────────────────────

class ECDSAWrapper(SchemeBase):
    """
    ECDSA com curva NIST P-256 (secp256r1) e hash SHA-256.
    Usa a biblioteca 'cryptography' (backend OpenSSL).

    Segurança clássica : ~128 bits
    Segurança quântica : QUEBRADO pelo algoritmo de Shor
    """
    name = "ECDSA P-256"

    def keygen(self) -> tuple[Any, Any]:
        sk = ec.generate_private_key(ec.SECP256R1())
        return sk.public_key(), sk

    def sign(self, sk: Any, msg: bytes) -> bytes:
        # ECDSA com hash SHA-256 embutido; a biblioteca assina o digest
        return sk.sign(msg, ec.ECDSA(hashes.SHA256()))

    def verify(self, pk: Any, msg: bytes, sig: bytes) -> bool:
        try:
            pk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def pk_to_bytes(self, pk: Any) -> bytes:
        # Ponto não-comprimido: 0x04 || x(32B) || y(32B) = 65 bytes para P-256
        return pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def sk_to_bytes(self, sk: Any) -> bytes:
        # Serialização PKCS#8 DER (~121 bytes para P-256)
        return sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())


# ── CRYSTALS-Dilithium ────────────────────────────────────────────────────────

class DilithiumWrapper(SchemeBase):
    """
    CRYSTALS-Dilithium via 'dilithium-py' (implementação Python puro).

    Nota: dilithium-py não usa otimizações SIMD/AVX. Implementações
    nativas (liboqs, pqclean) são tipicamente 10–50× mais rápidas.
    Os tamanhos de chave/assinatura são os mesmos em qualquer implementação.
    """

    def __init__(self, variant: Any, name: str) -> None:
        self._v = variant
        self.name = name

    def keygen(self) -> tuple[bytes, bytes]:
        return self._v.keygen()   # (pk, sk) já em bytes

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return self._v.sign(sk, msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        return self._v.verify(pk, msg, sig)

    def pk_to_bytes(self, pk: bytes) -> bytes:
        return pk   # já em bytes

    def sk_to_bytes(self, sk: bytes) -> bytes:
        return sk   # já em bytes


class DilithiumInstrumented(DilithiumWrapper):
    """
    Variante instrumentada do DilithiumWrapper que conta o número de
    iterações do loop de rejection sampling por chamada a sign().

    Implementa o algoritmo de assinatura do Dilithium com um contador de
    tentativas embutido, espelhando o código-fonte de dilithium-py.
    """

    def __init__(self, variant: Any, name: str) -> None:
        super().__init__(variant, name)
        self._last_attempts: int = 0     # tentativas na última assinatura
        self._attempts_list: list[int] = []

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        """
        Assina 'msg' e registra o número de tentativas (1 + rejeições).
        Retorna apenas a assinatura em bytes (compatível com SchemeBase).
        """
        sig, attempts = self._sign_counted(sk, msg)
        self._last_attempts = attempts
        self._attempts_list.append(attempts)
        return sig

    def _sign_counted(self, sk_bytes: bytes, m: bytes) -> tuple[bytes, int]:
        """
        Cópia do algoritmo Sign do dilithium-py com contador de iterações.
        Baseado no código-fonte de GiacomoPope/dilithium-py (licença MIT).
        """
        v = self._v

        # ── Descompactar chave privada ─────────────────────────────────────
        rho, K, tr, s1, s2, t0 = v._unpack_sk(sk_bytes)

        # ── Pré-computar A e μ ────────────────────────────────────────────
        A_hat = v._expand_matrix_from_seed(rho)         # A ∈ R_q^{k×l} (NTT)
        mu      = v._h(tr + m, 64)                      # hash da mensagem
        rho_prime = v._h(K + mu, 64)                    # semente para y

        # ── Pre-NTT dos segredos ──────────────────────────────────────────
        s1 = s1.to_ntt()
        s2 = s2.to_ntt()
        t0 = t0.to_ntt()

        alpha   = v.gamma_2 << 1    # 2*γ₂
        kappa   = 0                 # nonce (incrementado por l a cada iteração)
        attempt = 0                 # contador de tentativas

        while True:
            attempt += 1

            # ── Passo 3: Amostrar máscara y ───────────────────────────────
            y     = v._expand_mask_vector(rho_prime, kappa)
            y_hat = y.to_ntt()
            kappa += v.l              # próximo nonce

            # ── Passo 4–5: Calcular w e decompor ─────────────────────────
            w = (A_hat @ y_hat).from_ntt()
            w1, w0 = w.decompose(alpha)

            # ── Passo 6–7: Gerar desafio c ────────────────────────────────
            w1_bytes = w1.bit_pack_w(v.gamma_2)
            c_tilde  = v._h(mu + w1_bytes, 32)
            c        = v.R.sample_in_ball(c_tilde, v.tau)
            c        = c.to_ntt()

            # ── Passo 8–10: Calcular z e verificar normas (rejection) ─────
            z = y + (s1.scale(c)).from_ntt()
            if z.check_norm_bound(v.gamma_1 - v.beta):
                continue                                # REJEIÇÃO 1

            w0_minus_cs2 = w0 - s2.scale(c).from_ntt()
            if w0_minus_cs2.check_norm_bound(v.gamma_2 - v.beta):
                continue                                # REJEIÇÃO 2

            c_t0 = t0.scale(c).from_ntt()
            if c_t0.check_norm_bound(v.gamma_2):
                continue                                # REJEIÇÃO 3

            # ── Passo 11–12: Hints e verificação final ────────────────────
            w0_minus_cs2_plus_ct0 = w0_minus_cs2 + c_t0
            h = w0_minus_cs2_plus_ct0.make_hint_optimised(w1, alpha)
            if h.sum_hint() > v.omega:
                continue                                # REJEIÇÃO 4

            # ── Sucesso: empacotar assinatura ─────────────────────────────
            return v._pack_sig(c_tilde, z, h), attempt

    def rejection_stats(self) -> dict[str, float]:
        """Estatísticas das tentativas (1 = sem rejeição)."""
        if not self._attempts_list:
            return {}
        attempts = self._attempts_list
        rejections = [a - 1 for a in attempts]
        return {
            "media_tentativas" : statistics.mean(attempts),
            "media_rejeicoes"  : statistics.mean(rejections),
            "max_tentativas"   : max(attempts),
            "taxa_rejeicao"    : sum(r > 0 for r in rejections) / len(rejections),
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Estrutura de resultado
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class BenchmarkResult:
    name:          str
    keygen_times:  list[float] = field(default_factory=list)   # segundos
    sign_times:    list[float] = field(default_factory=list)
    verify_times:  list[float] = field(default_factory=list)
    pk_size:  int  = 0    # bytes
    sk_size:  int  = 0
    sig_size: int  = 0
    valid:    bool = True
    # Rejection sampling (apenas Dilithium)
    rej_stats: dict = field(default_factory=dict)

    # ── Propriedades computadas ────────────────────────────────────────────

    def _ms(self, lst: list[float]) -> tuple[float, float]:
        ms = [t * 1_000 for t in lst]
        if len(ms) < 2:
            return (ms[0] if ms else 0.0), 0.0
        return statistics.mean(ms), statistics.stdev(ms)

    @property
    def keygen_mean(self) -> float: return self._ms(self.keygen_times)[0]
    @property
    def keygen_std(self)  -> float: return self._ms(self.keygen_times)[1]
    @property
    def sign_mean(self)   -> float: return self._ms(self.sign_times)[0]
    @property
    def sign_std(self)    -> float: return self._ms(self.sign_times)[1]
    @property
    def verify_mean(self) -> float: return self._ms(self.verify_times)[0]
    @property
    def verify_std(self)  -> float: return self._ms(self.verify_times)[1]

    def as_csv_row(self) -> list:
        return [
            self.name,
            f"{self.keygen_mean:.4f}", f"{self.keygen_std:.4f}",
            f"{self.sign_mean:.4f}",   f"{self.sign_std:.4f}",
            f"{self.verify_mean:.4f}", f"{self.verify_std:.4f}",
            self.pk_size, self.sk_size, self.sig_size,
            self.valid,
            self.rej_stats.get("media_tentativas", "—"),
            self.rej_stats.get("taxa_rejeicao",    "—"),
        ]


# ══════════════════════════════════════════════════════════════════════════════
#  Verificação de sanidade
# ══════════════════════════════════════════════════════════════════════════════

def sanity_check(schemes: list[SchemeBase]) -> None:
    """
    Executa verificações básicas antes do benchmark:
      1. sign + verify retornam True para assinatura correta.
      2. verify retorna False para mensagem alterada.
      3. verify retorna False para assinatura corrompida.
    Aborta o programa se qualquer check falhar.
    """
    print("\n[Verificação de sanidade]")
    msg = b"sanity check message"

    for s in schemes:
        pk, sk = s.keygen()
        sig    = s.sign(sk, msg)

        # (a) Deve aceitar assinatura válida
        assert s.verify(pk, msg, sig), \
            f"FALHA: {s.name} verify rejeitou assinatura válida!"

        # (b) Deve rejeitar mensagem modificada
        assert not s.verify(pk, msg + b"\x00", sig), \
            f"FALHA: {s.name} verify aceitou mensagem alterada!"

        # (c) Deve rejeitar assinatura corrompida
        bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert not s.verify(pk, msg, bad_sig), \
            f"FALHA: {s.name} verify aceitou assinatura corrompida!"

        print(f"  ✓  {s.name}")

    print("  Tudo certo — iniciando benchmark.\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Motor do benchmark  (pseudocódigo do relatório → implementação direta)
# ══════════════════════════════════════════════════════════════════════════════

def _progress(phase: str, i: int, n: int, step: int) -> None:
    if (i + 1) % step == 0 or i == n - 1:
        pct = int((i + 1) / n * 100)
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r    {phase}  [{bar}] {pct:3d}%", end="", flush=True)


def run_benchmark(scheme: SchemeBase, n: int, msg: bytes) -> BenchmarkResult:
    """
    Executa as 4 fases do benchmark conforme pseudocódigo do relatório:
      Fase 1 — KeyGen   × N
      Fase 2 — Sign     × N
      Fase 3 — Verify   × N
      Fase 4 — Tamanhos (pk, sk, sig em bytes)
    """
    if n <= 0:
        raise Exception(f"Número Inválido de Operações: {n}")
    result = BenchmarkResult(name=scheme.name)
    step   = max(n // 20, 1)

    print(f"\n{'─' * 68}")
    print(f"  ▶  {scheme.name}  —  {n} iterações / operação")
    print(f"{'─' * 68}")

    # ── Fase 1: KeyGen ────────────────────────────────────────────────────
    print("  Fase 1/4 — KeyGen")
    for i in range(n):
        t0 = time.perf_counter()
        _, _ = scheme.keygen()
        result.keygen_times.append(time.perf_counter() - t0)
        _progress("KeyGen", i, n, step)
    print(f"\r  Fase 1/4 — KeyGen     "
          f"→  {result.keygen_mean:8.2f} ± {result.keygen_std:5.2f} ms")

    # Par fixo para as fases seguintes
    pk, sk = scheme.keygen()

    # ── Fase 2: Sign ──────────────────────────────────────────────────────
    print("  Fase 2/4 — Sign")
    for i in range(n):
        t0 = time.perf_counter()
        _sig = scheme.sign(sk, msg)
        result.sign_times.append(time.perf_counter() - t0)
        _progress("Sign  ", i, n, step)
    print(f"\r  Fase 2/4 — Sign       "
          f"→  {result.sign_mean:8.2f} ± {result.sign_std:5.2f} ms")

    # Assinatura fixa para verificação
    sig = scheme.sign(sk, msg)

    # ── Fase 3: Verify ────────────────────────────────────────────────────
    print("  Fase 3/4 — Verify")
    for i in range(n):
        t0 = time.perf_counter()
        ok = scheme.verify(pk, msg, sig)
        result.verify_times.append(time.perf_counter() - t0)
        _progress("Verify", i, n, step)
    result.valid = ok # type: ignore
    status = "✓" if ok else "✗  ATENÇÃO: verify FALHOU!" # type: ignore
    print(f"\r  Fase 3/4 — Verify     "
          f"→  {result.verify_mean:8.2f} ± {result.verify_std:5.2f} ms  {status}")

    # ── Fase 4: Tamanhos ──────────────────────────────────────────────────
    result.pk_size  = len(scheme.pk_to_bytes(pk))
    result.sk_size  = len(scheme.sk_to_bytes(sk))
    result.sig_size = len(sig)
    print(f"  Fase 4/4 — Tamanhos   "
          f"→  pk={result.pk_size} B    sk={result.sk_size} B    sig={result.sig_size} B")

    # ── Rejection sampling (apenas DilithiumInstrumented) ─────────────────
    if isinstance(scheme, DilithiumInstrumented):
        stats = scheme.rejection_stats()
        result.rej_stats = stats
        print(f"  Rejection sampling    "
              f"→  média {stats['media_tentativas']:.3f} tentativas/sign  "
              f"  taxa de rejeição {stats['taxa_rejeicao'] * 100:.1f}%")

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Exibição dos resultados
# ══════════════════════════════════════════════════════════════════════════════

def print_results(results: list[BenchmarkResult]) -> None:
    ref = results[0]   # ECDSA como referência para as razões

    def ratio(a: float, b: float) -> str:
        return f"{a / b:.2f}×" if b else "—"

    def fmt(mean: float, std: float) -> str:
        return f"{mean:8.2f} ±{std:5.2f}"

    # ── Tabela de tempos e tamanhos ───────────────────────────────────────
    cols  = [22, 18, 18, 18, 9, 10, 9]
    total = sum(cols) + (len(cols) - 1) * 4 + 4

    def hline(l, m, r, f="─"):
        parts = [f * c for c in cols]
        return l + (m + f).join(parts) + r

    header = (f"║ {"Esquema".center(cols[0])} │ " + " │ ".join(
        h.center(w+1) for h, w in zip(
            ["KeyGen (ms)", "Sign (ms)", "Verify (ms)",
             "pk (B)", "sk (B)", "sig (B)"], cols[1:]
        )) + " ║")

    print("\n" + "═" * total)
    print("  TABELA DE RESULTADOS")
    print("═" * total)
    print(hline("╔═", "═╤═", "═╗", "═"))
    print(header)
    print(hline("╠═", "═╪═", "═╣", "═"))

    for i, r in enumerate(results):
        cells = [
            r.name.ljust(cols[0]),
            fmt(r.keygen_mean, r.keygen_std).ljust(cols[1]+1),
            fmt(r.sign_mean,   r.sign_std).ljust(cols[2]+1),
            fmt(r.verify_mean, r.verify_std).ljust(cols[3]+1),
            str(r.pk_size).center(cols[4]+1),
            str(r.sk_size).center(cols[5]+1),
            str(r.sig_size).center(cols[6]+1),
        ]
        print("║ " + " │ ".join(cells) + " ║")
        if i < len(results) - 1:
            print(hline("╟─", "─┼─", "─╢", "─"))

    print(hline("╚═", "═╧═", "═╝", "═"))

    # ── Tabela de razões ──────────────────────────────────────────────────
    print(f"\n{'─' * total}")
    print("  RAZÕES EM RELAÇÃO AO ECDSA P-256  (Dilithium / ECDSA)")
    print(f"{'─' * total}")

    headers2 = ["Esquema", "KeyGen", "Sign", "Verify", "pk", "sk", "sig"]
    cols2 = [22, 10, 10, 10, 10, 10, 10]
    h2_line = "  " + "  ".join(h.ljust(w) for h, w in zip(headers2, cols2))
    sep2 = "  " + "  ".join("─" * w for w in cols2)
    print(h2_line)
    print(sep2)

    for r in results[1:]:
        cells2 = [
            r.name.ljust(cols2[0]),
            ratio(r.keygen_mean, ref.keygen_mean).ljust(cols2[1]),
            ratio(r.sign_mean,   ref.sign_mean).ljust(cols2[2]),
            ratio(r.verify_mean, ref.verify_mean).ljust(cols2[3]),
            ratio(r.pk_size,     ref.pk_size).ljust(cols2[4]),
            ratio(r.sk_size,     ref.sk_size).ljust(cols2[5]),
            ratio(r.sig_size,    ref.sig_size).ljust(cols2[6]),
        ]
        print("  " + "  ".join(cells2))

    # ── Notas finais ──────────────────────────────────────────────────────
    print(f"\n{'═' * total}")
    print("  OBSERVAÇÕES")
    print(f"{'─' * total}")
    notes = [
        "Tempos: time.perf_counter() (resolução ns), média aritmética, desvio padrão.",
        "dilithium-py é Python puro — sem SIMD/AVX; implementações C são 10–50× mais rápidas.",
        "Tamanhos são determinísticos (não dependem da implementação).",
        "ECDSA P-256 : ~128 bits de segurança clássica — VULNERÁVEL ao algoritmo de Shor.",
        "Dilithium2  : NIST Level 2 (~128 bits quânticos) — RESISTENTE a ataques quânticos.",
        "Dilithium3  : NIST Level 3 (~192 bits quânticos) — RESISTENTE a ataques quânticos.",
    ]
    for note in notes:
        print(f"  • {note}")
    print("═" * total + "\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Exportação CSV
# ══════════════════════════════════════════════════════════════════════════════

def export_csv(results: list[BenchmarkResult], path: str) -> None:
    """Salva os resultados em CSV para análise posterior (Excel, R, Python)."""
    fieldnames = [
        "esquema",
        "keygen_media_ms", "keygen_std_ms",
        "sign_media_ms",   "sign_std_ms",
        "verify_media_ms", "verify_std_ms",
        "pk_bytes", "sk_bytes", "sig_bytes",
        "valido",
        "media_tentativas_sign", "taxa_rejeicao",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(fieldnames)
        for r in results:
            w.writerow(r.as_csv_row())
    print(f"  Resultados exportados → '{path}'")


# ══════════════════════════════════════════════════════════════════════════════
#  Interface de linha de comando
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Benchmark: ECDSA P-256 vs CRYSTALS-Dilithium (ML-DSA / FIPS 204)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python benchmark.py --quick          # 20 iterações, rápido\n"
            "  python benchmark.py -n 200           # 200 iterações\n"
            "  python benchmark.py --csv dados.csv  # salvar em CSV\n"
        ),
    )
    p.add_argument("-n", "--iterations", type=int, default=DEFAULT_N,
                   help=f"Iterações por operação (padrão: {DEFAULT_N})")
    p.add_argument("--quick", action="store_true",
                   help="Modo rápido: usa 20 iterações (útil para testes)")
    p.add_argument("--csv", metavar="ARQUIVO",
                   help="Exportar resultados para arquivo CSV")
    p.add_argument("--no-rejection", action="store_true",
                   help="Desabilitar contagem de rejection sampling (mais rápido)")
    return p.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
#  Ponto de entrada
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    args = parse_args()
    n    = 20 if args.quick else args.iterations

    print(
        "\n╔══════════════════════════════════════════════════════════════════════╗\n"
        "║  Benchmark: Assinaturas Digitais Pós-Quânticas vs. Clássicas         ║\n"
        "╠══════════════════════════════════════════════════════════════════════╣\n"
        f"║  Esquemas  : ECDSA P-256  ×  Dilithium2  ×  Dilithium3               ║\n"
        f"║  Iterações : {n:<10}  │  Mensagem: {len(TEST_MSG)} bytes{'':<17}     ║\n"
        "╚══════════════════════════════════════════════════════════════════════╝"
    )

    # Escolher wrapper de Dilithium (com ou sem contagem de rejeições)
    if args.no_rejection:
        dil2 = DilithiumWrapper(Dilithium2, "Dilithium2")
        dil3 = DilithiumWrapper(Dilithium3, "Dilithium3")
    else:
        dil2 = DilithiumInstrumented(Dilithium2, "Dilithium2")
        dil3 = DilithiumInstrumented(Dilithium3, "Dilithium3")

    schemes: list[SchemeBase] = [
        ECDSAWrapper(),
        dil2,
        dil3,
    ]

    sanity_check(schemes)

    results: list[BenchmarkResult] = []
    for s in schemes:
        r = run_benchmark(s, n=n, msg=TEST_MSG)
        results.append(r)

    print_results(results)

    if args.csv:
        export_csv(results, args.csv)


if __name__ == "__main__":
    main()
