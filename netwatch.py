"""TShark -> window features -> Laya/rules -> labeled evaluation."""
import argparse
import csv
import json
import math
import subprocess
import sys
from pathlib import Path

LABELS = ("normal", "port_scan", "dns_activity", "connection_burst", "unknown")
FIELDS = ("frame.time_epoch", "frame.len", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags.syn",
          "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin", "dns.flags.response",
          "icmp.type", "icmpv6.type")
QUESTIONS = {
    "activity": {"type": "choice", "instructions": "Classify this network observation.",
                 "criteria": {"normal": "ordinary network traffic", "port_scan": "many destination ports and TCP SYN attempts",
                              "dns_activity": "DNS queries dominate", "connection_burst": "many connections or packets to few ports",
                              "unknown": "insufficient or mixed evidence"}},
    "suspicion": {"type": "score", "instructions": "How suspicious is this traffic?",
                  "criteria": ["ordinary", "slightly unusual", "suspicious", "highly suspicious"]},
    "needs_review": {"type": "noul", "instructions": "Does this traffic warrant security analyst review?"},
}


def tshark_rows(pcap, executable):
    command = [executable, "-r", str(pcap), "-T", "fields", "-E", "separator=/t",
               "-E", "quote=n", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(("-e", field))
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise RuntimeError(f"TShark tidak ditemukan: {executable}") from exc
    if result.returncode:
        raise RuntimeError(f"TShark gagal membaca {pcap}: {result.stderr.strip()}")
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != len(FIELDS):
            raise RuntimeError(f"Output TShark {len(parts)} kolom, perlu {len(FIELDS)}")
        yield dict(zip(FIELDS, parts))


def fresh(pcap, start, seconds):
    return {"pcap": str(pcap), "start_epoch": round(start, 6), "window_seconds": seconds,
            "packet_count": 0, "bytes_total": 0, "tcp_count": 0, "udp_count": 0,
            "icmp_count": 0, "dns_query_count": 0, "syn_only_count": 0, "ack_count": 0,
            "rst_count": 0, "fin_count": 0, "_src_ips": set(), "_dst_ips": set(),
            "_src_ports": set(), "_dst_ports": set(), "_syn_dst_ports": set()}


def add_packet(bucket, row):
    bucket["packet_count"] += 1
    bucket["bytes_total"] += int(row["frame.len"] or 0)
    src, dst = row["ip.src"] or row["ipv6.src"], row["ip.dst"] or row["ipv6.dst"]
    if src:
        bucket["_src_ips"].add(src)
    if dst:
        bucket["_dst_ips"].add(dst)
    tcp = bool(row["tcp.srcport"] or row["tcp.dstport"])
    udp = bool(row["udp.srcport"] or row["udp.dstport"])
    if tcp:
        bucket["tcp_count"] += 1
        syn = row["tcp.flags.syn"].lower() in {"1", "true"}
        ack = row["tcp.flags.ack"].lower() in {"1", "true"}
        bucket["syn_only_count"] += int(syn and not ack)
        if syn and not ack and row["tcp.dstport"]:
            bucket["_syn_dst_ports"].add(row["tcp.dstport"])
        bucket["ack_count"] += int(ack)
        bucket["rst_count"] += int(row["tcp.flags.reset"].lower() in {"1", "true"})
        bucket["fin_count"] += int(row["tcp.flags.fin"].lower() in {"1", "true"})
    elif udp:
        bucket["udp_count"] += 1
    if row["icmp.type"] or row["icmpv6.type"]:
        bucket["icmp_count"] += 1
    for key, value in (("_src_ports", row["tcp.srcport"] or row["udp.srcport"]),
                       ("_dst_ports", row["tcp.dstport"] or row["udp.dstport"])):
        if value:
            bucket[key].add(value)
    bucket["dns_query_count"] += int(row["dns.flags.response"] == "0")


def finish(bucket):
    result = {k: v for k, v in bucket.items() if not k.startswith("_")}
    for name in ("src_ips", "dst_ips", "src_ports", "dst_ports", "syn_dst_ports"):
        result["unique_" + name] = len(bucket["_" + name])
    count, seconds = result["packet_count"], result["window_seconds"]
    result.update(packets_per_second=round(count / seconds, 4),
                  average_packet_size=round(result["bytes_total"] / count, 4),
                  syn_ack_ratio=round(result["syn_only_count"] / max(result["ack_count"], 1), 4),
                  rst_tcp_ratio=round(result["rst_count"] / max(result["tcp_count"], 1), 4),
                  unique_dst_ports_per_second=round(result["unique_dst_ports"] / seconds, 4),
                  dns_queries_per_second=round(result["dns_query_count"] / seconds, 4))
    return result


def windows(rows, pcap, seconds):
    anchor = index = bucket = None
    for row in rows:
        try:
            timestamp = float(row["frame.time_epoch"])
        except ValueError:
            continue
        if not math.isfinite(timestamp) or timestamp <= 0:
            continue
        if anchor is None:
            anchor = timestamp
        next_index = max(0, math.floor((timestamp - anchor) / seconds + 1e-9))
        if next_index != index:
            if bucket is not None:
                yield finish(bucket)
            index, bucket = next_index, fresh(pcap, anchor + next_index * seconds, seconds)
        add_packet(bucket, row)
    if bucket is not None:
        yield finish(bucket)


def rules(feature):
    ports, syn, dns, count = (feature[k] for k in
                              ("unique_syn_dst_ports", "syn_only_count", "dns_query_count", "packet_count"))
    if ports >= 20 and syn >= 20:
        activity = "port_scan"
    elif dns >= 10 and dns / max(count, 1) >= 0.4:
        activity = "dns_activity"
    elif feature["packets_per_second"] >= 100 and ports < 20:
        activity = "connection_burst"
    else:
        activity = "normal"
    return {"activity": activity, "confidence": None, "suspicion_score": None, "needs_review": None}


def laya_decision(feature, router, model):
    state = {k: v for k, v in feature.items() if k not in {"pcap", "label", "start_epoch"}}
    result = router.predict(state, QUESTIONS, model=model)
    answers = result["answers"]
    activity = answers["activity"]["choice"]
    if activity not in LABELS:
        raise ValueError(f"Label Laya tidak dikenal: {activity}")
    return {"activity": activity, "confidence": answers["activity"].get("confidence"),
            "suspicion_score": answers["suspicion"].get("score"),
            "needs_review": answers["needs_review"].get("noul"), "raw_laya": result}


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def write_dashboard(path, predictions, report):
    directory = Path(__file__).parent / "dashboard"
    page = (directory / "index.html").read_text(encoding="utf-8")
    style = (directory / "style.css").read_text(encoding="utf-8")
    script = (directory / "app.js").read_text(encoding="utf-8")
    data = json.dumps({"predictions": predictions, "metrics": report}, ensure_ascii=False, default=str)
    data = data.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    page = page.replace('<link rel="stylesheet" href="style.css">', f"<style>{style}</style>")
    page = page.replace('<script src="app.js"></script>',
                        f"<script>window.NETWATCH_DATA={data};</script><script>{script}</script>")
    path.write_text(page, encoding="utf-8")


def metrics(rows, engine):
    pairs = [(r["label"], r["prediction"]["activity"]) for r in rows if r["engine"] == engine]
    matrix = {a: {b: 0 for b in LABELS} for a in LABELS}
    for actual, predicted in pairs:
        matrix[actual][predicted] += 1
    per_class = {}
    for label in LABELS:
        tp = matrix[label][label]
        support = sum(matrix[label].values())
        predicted = sum(matrix[actual][label] for actual in LABELS)
        precision = tp / predicted if predicted else 0
        recall = tp / support if support else 0
        per_class[label] = {"support": support, "precision": precision, "recall": recall,
                            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0}
    present = [v["f1"] for v in per_class.values() if v["support"]]
    return {"samples": len(pairs), "accuracy": sum(a == b for a, b in pairs) / len(pairs) if pairs else None,
            "macro_f1_present_classes": sum(present) / len(present) if present else None,
            "per_class": per_class, "confusion_matrix": matrix}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    extract = sub.add_parser("extract")
    extract.add_argument("--pcap", type=Path, required=True)
    extract.add_argument("--out", type=Path, required=True)
    predict = sub.add_parser("predict")
    predict.add_argument("--input", type=Path, required=True)
    predict.add_argument("--out", type=Path, required=True)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--manifest", type=Path, required=True)
    evaluate.add_argument("--out-dir", type=Path, required=True)
    for command in (extract, evaluate):
        command.add_argument("--tshark", default="tshark")
        command.add_argument("--window", type=float, default=5)
    for command in (predict, evaluate):
        command.add_argument("--engine", choices=("laya", "rules", "both"), default="both")
        command.add_argument("--model", choices=("english", "multilingual", "typed-decisions"), default="english")
    args = parser.parse_args(argv)
    if hasattr(args, "window") and (not math.isfinite(args.window) or args.window <= 0):
        parser.error("--window harus angka positif")
    try:
        if args.command == "extract":
            if not args.pcap.is_file():
                raise ValueError(f"PCAP tidak ada: {args.pcap}")
            observations = list(windows(tshark_rows(args.pcap, args.tshark), args.pcap, args.window))
            write_jsonl(args.out, observations)
            print(f"{len(observations)} jendela -> {args.out}")
            return 0
        if args.command == "evaluate":
            with args.manifest.open(newline="", encoding="utf-8-sig") as handle:
                manifest = list(csv.DictReader(handle))
            if not manifest or any("pcap" not in row or "label" not in row for row in manifest):
                raise ValueError("Manifest perlu kolom pcap,label dan minimal satu baris")
            observations = []
            for entry in manifest:
                label = entry["label"].strip()
                if label not in LABELS:
                    raise ValueError(f"Label tidak dikenal: {label}")
                pcap = (args.manifest.parent / entry["pcap"].strip()).resolve()
                if not pcap.is_file():
                    raise ValueError(f"PCAP tidak ada: {pcap}")
                group = list(windows(tshark_rows(pcap, args.tshark), pcap, args.window))
                if not group:
                    raise ValueError(f"Tidak ada paket bertimestamp valid: {pcap}")
                observations.extend({**item, "label": label} for item in group)
            args.out_dir.mkdir(parents=True, exist_ok=True)
            write_jsonl(args.out_dir / "observations.jsonl", observations)
        else:
            with args.input.open(encoding="utf-8") as handle:
                observations = [json.loads(line) for line in handle if line.strip()]
        router = None
        if args.engine in {"laya", "both"}:
            try:
                from laya import Router
            except ImportError as exc:
                raise RuntimeError("Laya belum terpasang; lihat README") from exc
            router = Router()
        engines = ("rules", "laya") if args.engine == "both" else (args.engine,)
        predictions = []
        for feature in observations:
            for engine in engines:
                decision = rules(feature) if engine == "rules" else laya_decision(feature, router, args.model)
                predictions.append({"pcap": feature["pcap"], "start_epoch": feature["start_epoch"],
                                    "label": feature.get("label"), "engine": engine,
                                    "features": feature, "prediction": decision})
        output = args.out_dir / "predictions.jsonl" if args.command == "evaluate" else args.out
        write_jsonl(output, predictions)
        if args.command == "evaluate":
            columns = ("pcap", "start_epoch", "label", "engine", "activity", "correct",
                       "confidence", "suspicion_score", "needs_review", "packet_count",
                       "unique_dst_ports", "unique_syn_dst_ports", "syn_only_count", "dns_query_count")
            with (args.out_dir / "predictions.csv").open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns)
                writer.writeheader()
                for item in predictions:
                    feat, pred = item["features"], item["prediction"]
                    writer.writerow({"pcap": item["pcap"], "start_epoch": item["start_epoch"],
                                     "label": item["label"], "engine": item["engine"],
                                     "activity": pred["activity"], "correct": int(pred["activity"] == item["label"]),
                                     "confidence": pred["confidence"], "suspicion_score": pred["suspicion_score"],
                                     "needs_review": pred["needs_review"], **{k: feat[k] for k in columns[9:]}})
            report = {engine: metrics(predictions, engine) for engine in engines}
            (args.out_dir / "metrics.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            write_dashboard(args.out_dir / "dashboard.html", predictions, report)
            print(json.dumps({k: {"samples": v["samples"], "accuracy": v["accuracy"],
                                   "macro_f1_present_classes": v["macro_f1_present_classes"]}
                              for k, v in report.items()}, indent=2))
        print(f"{len(observations)} jendela, {len(predictions)} prediksi -> {output}")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, csv.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
