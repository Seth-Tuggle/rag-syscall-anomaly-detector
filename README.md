# RAG-assisted Syscall Anomaly Detector

My CS645 security project compares system-call traces with known program
baselines. I use syscall arguments, call frequencies, and sequences to look for
changes in behavior, with optional retrieval and an LLM explanation of the result.

## Run locally

Install `requirements.txt` in a Python environment. Run these commands from the
repository root so the detector can find the included trace files:

```bash
python rag_anomaly_detector.py --program chrome --trace cleaned_chrome.trace --skip-llm
python rag_anomaly_detector.py --program chrome --trace chrome_like_suspicious_severe.trace --skip-llm
```

These examples use `--skip-llm` to run the behavior scoring without calling an
external API. For retrieval and LLM explanations, set your own `OPENAI_API_KEY`
and run once with `--rebuild-index`, without `--skip-llm`. That mode uses a paid
API. The detector generates baseline statistics and embedding caches locally;
I keep those files out of version control.

## How I interpret the results

The heuristic score determines the anomaly verdict. The LLM explains that verdict
without overriding it. My thresholds are experimental, and this project isn't a
validated malware classifier.

The example traces include simulated suspicious behavior, with local usernames
and private network addresses anonymized. Both `normal_test.trace` and
`suspicious_test.trace` currently trigger the detector, so I don't treat their
filenames as reliable classification labels.

## Ownership

For details about my contributions and project attribution, see [CREDITS.md](CREDITS.md).
