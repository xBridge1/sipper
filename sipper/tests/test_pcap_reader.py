import pytest

from ciper.pcap_reader import PcapInputError, iter_pcap, read_pcap


def test_iter_pcap_rejects_missing_file(tmp_path):
    missing_file = tmp_path / "missing.pcap"

    with pytest.raises(PcapInputError, match="nao encontrado"):
        list(iter_pcap(missing_file))


def test_iter_pcap_rejects_unsupported_file_extension(tmp_path):
    capture_file = tmp_path / "capture.txt"
    capture_file.write_bytes(b"not a capture")

    with pytest.raises(PcapInputError, match=".pcap ou .pcapng"):
        list(iter_pcap(capture_file))


def test_read_pcap_rejects_empty_capture(tmp_path):
    capture_file = tmp_path / "empty.pcap"
    capture_file.write_bytes(b"")

    with pytest.raises(PcapInputError, match="vazio"):
        read_pcap(capture_file)
