# RAG-assisted Syscall Anomaly Detector

## Historical coursework

I'm keeping this older CS645 project to describe my work and preserve the main
code. It isn't maintained as a standalone application. Reproducing the original
class environment and configuration may be necessary; dependencies and API
choices may now be outdated or deprecated.

## About the project

My project compares system-call traces with known program baselines. I use
syscall arguments, call frequencies, and sequences to look for changes in
behavior, with optional retrieval and an LLM explanation of the result.

- `rag_anomaly_detector.py`: trace parsing, behavior profiles, anomaly scoring,
  retrieval, and explanations.
- `make_test_traces.py`: example trace generation.
- The included `.trace` files: baseline and simulated suspicious behavior.

## Original environment and limitations

The Python scripts expect the trace files and configuration used for the class
project. The `--skip-llm` option runs behavior scoring without external API calls;
retrieval and LLM explanations require configured API access. Generated statistics
and caches are kept out of version control.

The heuristic score determines the verdict; the LLM explains it without
overriding it. My thresholds are experimental, not a validated malware classifier.
Both `normal_test.trace` and `suspicious_test.trace` trigger the current detector,
so their filenames aren't reliable classification labels. Local usernames and
private network addresses in the example traces have been anonymized.

## Ownership

For details about my contributions and project attribution, see [CREDITS.md](CREDITS.md).
