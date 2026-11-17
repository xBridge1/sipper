LOSS_TARGET_PERCENT = 0.10
LOSS_HIGH_QUALITY_PERCENT = 1.0
LOSS_SEVERE_PERCENT = 5.0
JITTER_IDEAL_MS = 5.0
JITTER_HIGH_QUALITY_MS = 30.0
JITTER_SEVERE_MS = 100.0


# ITU-T G.113 Appendix I: equipment impairment (Ie) and packet-loss
# robustness (Bpl) per codec, assuming the codec's usual concealment.
CODEC_IMPAIRMENTS = {
    "PCMU": (0.0, 25.1),
    "PCMA": (0.0, 25.1),
    "G722": (0.0, 25.1),
    "G729": (11.0, 19.0),
    "G723": (15.0, 16.1),
    "GSM": (20.0, 10.0),
    "ILBC": (10.0, 32.0),
    "OPUS": (0.0, 30.0),
    "AMR": (5.0, 10.0),
    "AMR-WB": (0.0, 15.0),
}
DEFAULT_CODEC_IMPAIRMENT = (0.0, 25.1)
# Mouth-to-ear delay not visible in the capture: codec framing, look-ahead
# and playout (jitter buffer sized at roughly twice the jitter).
CODEC_PROCESSING_DELAY_MS = 30.0


def estimate_mos(loss_percent, jitter_seconds, codec=None, rtt_seconds=None, burst_ratio=1.0):
    """Estimate MOS-CQE with a simplified ITU-T G.107 E-model.

    R = 93.2 - Id - Ie,eff, where Ie,eff grows with loss according to the codec's
    robustness and Id comes from the estimated one-way delay. Without RTCP
    the network delay is unknown and only jitter buffering is counted.
    """
    loss_percent = max(0.0, float(loss_percent or 0.0))
    jitter_ms = max(0.0, float(jitter_seconds or 0.0) * 1000)
    ie, bpl = CODEC_IMPAIRMENTS.get(str(codec or "").upper(), DEFAULT_CODEC_IMPAIRMENT)
    burst_ratio = max(1.0, float(burst_ratio or 1.0))
    ie_effective = ie + (95.0 - ie) * loss_percent / (loss_percent / burst_ratio + bpl)

    one_way_delay = CODEC_PROCESSING_DELAY_MS + 2 * jitter_ms
    if rtt_seconds:
        one_way_delay += max(0.0, rtt_seconds) * 1000 / 2
    delay_impairment = 0.024 * one_way_delay
    if one_way_delay > 177.3:
        delay_impairment += 0.11 * (one_way_delay - 177.3)

    rating = max(0.0, min(100.0, 93.2 - delay_impairment - ie_effective))
    mos = 1.0 + 0.035 * rating + rating * (rating - 60.0) * (100.0 - rating) * 0.000007
    return round(max(1.0, min(4.5, mos)), 2)


def mos_observation(mos):
    if mos >= 4.0:
        state = "boa"
    elif mos >= 3.5:
        state = "aceitavel"
    elif mos >= 3.0:
        state = "degradada"
    else:
        state = "ruim"

    return f"MOS estimado: {mos:.2f} ({state}). Estimativa E-model (ITU-T G.107) com perda, jitter, codec e RTT do RTCP quando disponivel."


def packet_loss_observation(loss_percent):
    if loss_percent <= LOSS_TARGET_PERCENT:
        state = "Excelente"
    elif loss_percent < LOSS_HIGH_QUALITY_PERCENT:
        state = "Atencao"
    elif loss_percent < LOSS_SEVERE_PERCENT:
        state = "Degradada"
    else:
        state = "Critica"

    return (
        f"Perda {state.lower()}: {loss_percent:.2f}%. Alvo operacional: ate "
        f"{LOSS_TARGET_PERCENT:.2f}%; voz de alta qualidade: abaixo de "
        f"{LOSS_HIGH_QUALITY_PERCENT:.0f}%; critica: {LOSS_SEVERE_PERCENT:.0f}% ou mais."
    )


def jitter_observation(average_seconds, maximum_seconds):
    average_ms = average_seconds * 1000
    maximum_ms = maximum_seconds * 1000

    if maximum_ms <= JITTER_IDEAL_MS:
        state = "Excelente"
    elif maximum_ms <= JITTER_HIGH_QUALITY_MS:
        state = "Aceitavel"
    elif maximum_ms <= JITTER_SEVERE_MS:
        state = "Degradado"
    else:
        state = "Critico"

    return (
        f"Jitter {state.lower()}: medio {average_ms:.1f} ms, maximo {maximum_ms:.1f} ms. "
        f"Ideal: ate {JITTER_IDEAL_MS:.0f} ms; voz de alta qualidade: ate "
        f"{JITTER_HIGH_QUALITY_MS:.0f} ms; critico: acima de {JITTER_SEVERE_MS:.0f} ms."
    )


def quality_reference_note():
    return (
        "Referencia VoIP: perda abaixo de 1% e jitter abaixo de 30 ms favorecem alta "
        "qualidade. Buffer de jitter e codec podem alterar o impacto percebido."
    )
