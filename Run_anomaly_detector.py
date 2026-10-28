import argparse
from pathlib import Path

from rag_anomaly_detector import analyze


TEST_CASES = [
    ("firefox", "cleaned_firefox.trace", "expected normal"),
    ("chrome", "chrome_like.trace", "expected normal-ish"),
    ("firefox", "firefox_like_suspicious_mild.trace", "expected anomaly"),
    ("firefox", "firefox_like_suspicious_severe.trace", "expected anomaly"),
    ("chrome", "chrome_like_suspicious_severe.trace", "expected anomaly"),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick smoke test for rag_anomaly_detector.py")
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Run deterministic scoring only. Omit this when the OpenAI API is available.",
    )
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Rebuild baseline behavior stats and the RAG index before the first test.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    print("Running quick RAG anomaly detector tests")
    print(f"Mode: {'deterministic only' if args.skip_llm else 'RAG + LLM'}")
    print()

    for i, (program, trace_name, expectation) in enumerate(TEST_CASES, start=1):
        trace_path = root / trace_name
        print(f"\n[{i}/{len(TEST_CASES)}] {trace_name} ({program}, {expectation})")
        print("-" * 72)
        analyze(
            program=program,
            trace_path=str(trace_path),
            rebuild_index=args.rebuild_index and i == 1,
            skip_llm=args.skip_llm,
        )


if __name__ == "__main__":
    main()
