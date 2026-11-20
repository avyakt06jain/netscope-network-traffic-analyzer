# Contributing to FrameSight

Thank you for helping improve this educational network analyzer. Keep changes focused on correct, explainable Computer Networks behavior and safe handling of authorized packet data.

## Development setup

```bash
python -m venv .venv
# Activate .venv for your operating system
python -m pip install -r requirements.txt
python scripts/generate_demo_pcap.py
pytest -q
ruff check .
```

Run the application with:

```bash
streamlit run app.py
```

## Pull requests

- Keep parsing, filtering, aggregation and capture lifecycle logic independent of Streamlit where possible.
- Add or update offline tests for behavioral changes. Tests must not require internet access, administrator/root privileges or live capture.
- Never commit a real network capture. Only the deterministic `samples/framesight_demo.pcap` is allowed by `.gitignore`.
- Do not add raw payload export, credential collection, packet injection, stealth capture or claims that heuristics prove an attack.
- Preserve clear `DEMO SAMPLE`, `IMPORTED PCAP` and `LIVE CAPTURE` labeling.
- Run the generator, test suite and Ruff before opening a pull request.

## Deterministic sample rule

Changes to `scripts/generate_demo_pcap.py` must regenerate exactly reproducible bytes. CI runs the generator and fails if the resulting PCAP differs from the committed sample.

## Reporting bugs

Include the operating system, Python version, FrameSight mode, a minimal reproduction and the friendly error message. Do not attach packet captures containing private or unauthorized traffic.
