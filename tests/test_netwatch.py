import csv
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import netwatch


def packet(time, **values):
    row = dict.fromkeys(netwatch.FIELDS, "")
    row.update({"frame.time_epoch": str(time), "frame.len": "60", "ip.src": "127.0.0.1",
                "ip.dst": "127.0.0.1", **values})
    return row


class WindowTests(unittest.TestCase):
    def test_laya_result_mapping(self):
        test_case = self
        class FakeRouter:
            def predict(self, state, questions, model):
                test_case.assertNotIn("pcap", state)
                test_case.assertEqual(model, "english")
                test_case.assertEqual(questions["activity"]["type"], "choice")
                return {"answers": {"activity": {"choice": "port_scan", "confidence": 0.8},
                                    "suspicion": {"score": 2.5}, "needs_review": {"noul": 0.7}}}

        feature = {"pcap": "x.pcap", "start_epoch": 1, "packet_count": 30}
        result = netwatch.laya_decision(feature, FakeRouter(), "english")
        self.assertEqual(result["activity"], "port_scan")
        self.assertEqual(result["needs_review"], 0.7)

    def test_real_tshark_reads_tiny_pcap(self):
        tshark = shutil.which("tshark") or Path(r"C:\Program Files\Wireshark\tshark.exe")
        if not Path(tshark).is_file():
            self.skipTest("TShark belum terpasang")
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        ipv4 = bytes.fromhex("4500002800010000400600007f0000017f000001")
        tcp = struct.pack("!HHIIHHHH", 50000, 80, 0, 0, 0x5002, 8192, 0, 0)
        frame = ethernet + ipv4 + tcp
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "tiny.pcap"
            pcap.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
                             + struct.pack("<IIII", 100, 0, len(frame), len(frame)) + frame)
            result = list(netwatch.windows(netwatch.tshark_rows(pcap, str(tshark)), pcap, 5))
        self.assertEqual(result[0]["packet_count"], 1)
        self.assertEqual(result[0]["syn_only_count"], 1)
        self.assertEqual(result[0]["unique_dst_ports"], 1)

    def test_windows_and_features(self):
        rows = [packet(100, **{"tcp.srcport": "50000", "tcp.dstport": "80", "tcp.flags.syn": "1"}),
                packet(101, **{"tcp.srcport": "50001", "tcp.dstport": "81", "tcp.flags.syn": "1",
                               "tcp.flags.reset": "1"}),
                packet(105, **{"udp.srcport": "51000", "udp.dstport": "53", "dns.flags.response": "0"})]
        result = list(netwatch.windows(rows, "test.pcap", 5))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["syn_only_count"], 2)
        self.assertEqual(result[0]["unique_dst_ports"], 2)
        self.assertEqual(result[0]["unique_syn_dst_ports"], 2)
        self.assertEqual(result[0]["rst_tcp_ratio"], 0.5)
        self.assertEqual(result[1]["dns_query_count"], 1)
        self.assertEqual(result[1]["start_epoch"], 105)

    def test_metrics_counts_wrong_prediction(self):
        rows = [{"label": "normal", "engine": "rules", "prediction": {"activity": "normal"}},
                {"label": "port_scan", "engine": "rules", "prediction": {"activity": "normal"}}]
        report = netwatch.metrics(rows, "rules")
        self.assertEqual(report["accuracy"], 0.5)
        self.assertEqual(report["confusion_matrix"]["port_scan"]["normal"], 1)
        self.assertEqual(report["per_class"]["port_scan"]["recall"], 0)

    def test_evaluate_writes_dashboard_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.pcapng").touch()
            with (root / "manifest.csv").open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=("pcap", "label"))
                writer.writeheader()
                writer.writerow({"pcap": "sample.pcapng", "label": "normal"})
            with patch.object(netwatch, "tshark_rows", return_value=iter([packet(100)])):
                code = netwatch.main(["evaluate", "--manifest", str(root / "manifest.csv"),
                                      "--out-dir", str(root / "out"), "--engine", "rules"])
            self.assertEqual(code, 0)
            result = json.loads((root / "out" / "metrics.json").read_text())
            self.assertEqual(result["rules"]["accuracy"], 1)
            prediction = json.loads((root / "out" / "predictions.jsonl").read_text())
            self.assertEqual(prediction["prediction"]["activity"], "normal")
            self.assertTrue((root / "out" / "predictions.csv").exists())
            self.assertIn("NETWATCH_DATA", (root / "out" / "dashboard.html").read_text())


if __name__ == "__main__":
    unittest.main()
