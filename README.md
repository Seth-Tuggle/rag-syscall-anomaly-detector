# RAG-assisted Syscall Anomaly Detector

A CS645 security project for comparing system-call traces with known program
baselines. The detector parses syscall arguments, builds behavior profiles,
compares distributions and call sequences, scores suspicious activity, and
optionally retrieves baseline windows for an LLM explanation.

## Run locally

Install `requirements.txt` in a Python environment. Run commands from the
repository root so the bundled trace files can be found.

```bash
python rag_anomaly_detector.py --program chrome --trace cleaned_chrome.trace --skip-llm
python rag_anomaly_detector.py --program chrome --trace chrome_like_suspicious_severe.trace --skip-llm
```

For retrieval and LLM explanations, set `OPENAI_API_KEY` using your own account
and run with `--rebuild-index` once, without `--skip-llm`. This calls a paid
external API. Baseline statistics and embedding caches are regenerated locally
and excluded from version control. No API calls were made during recovery.

## Design and limitations

The final anomaly verdict is determined by heuristic behavior scoring; the LLM
explains the result rather than overriding it. Thresholds are experimental and
are not a validated malware classifier. Trace examples include simulated
suspicious behavior. Local usernames/private network addresses were anonymized.
The original API connectivity script was omitted from the test discovery path.

See `RECOVERY_NOTES.md` for snapshot provenance.

Legacy files named `normal_test.trace` and `suspicious_test.trace` both trigger the
current detector. Their filenames are not verified classification labels.
