import os
import pandas as pd

import app


# ---------------------------------------------------------------------------
# IAM_EVENT_SCHEMA — isomorphism guardrail
# ---------------------------------------------------------------------------
def test_schema_field_names_are_unique():
    field_names = [f for f, _, _ in app.IAM_EVENT_SCHEMA]
    assert len(field_names) == len(set(field_names))


def test_schema_has_positive_pdf_widths():
    for field, header, width in app.IAM_EVENT_SCHEMA:
        assert width > 0
        assert isinstance(header, str) and header


# ---------------------------------------------------------------------------
# risk_badge_html
# ---------------------------------------------------------------------------
def test_risk_badge_html_known_levels():
    assert 'critical' in app.risk_badge_html('CRITICAL')
    assert 'high' in app.risk_badge_html('High')
    assert 'medium' in app.risk_badge_html('medium risk')


def test_risk_badge_html_unknown_level_falls_back_to_info():
    html = app.risk_badge_html('SOMETHING_WEIRD')
    assert 'risk-badge info' in html


def test_risk_badge_html_empty_string():
    html = app.risk_badge_html('')
    assert 'risk-badge info' in html


# ---------------------------------------------------------------------------
# highlight_* row stylers — used by df.style.apply(axis=1)
# ---------------------------------------------------------------------------
def test_highlight_risk_critical_row():
    row = pd.Series({'risk_level': 'CRITICAL', 'username': 'alice'})
    styles = app.highlight_risk(row)
    assert len(styles) == len(row)
    assert all('ff8095' in s for s in styles)


def test_highlight_risk_unrecognized_level_is_unstyled():
    row = pd.Series({'risk_level': 'UNKNOWN', 'username': 'alice'})
    styles = app.highlight_risk(row)
    assert all(s == '' for s in styles)


def test_highlight_drift_risk_high_vs_medium():
    high_row = pd.Series({'risk': 'HIGH RISK - unused', 'username': 'alice'})
    med_row = pd.Series({'risk': 'MEDIUM RISK - rare', 'username': 'bob'})
    assert 'ff8095' in app.highlight_drift_risk(high_row)[0]
    assert 'ffe066' in app.highlight_drift_risk(med_row)[0]


def test_highlight_hygiene_risk_info_level():
    row = pd.Series({'risk': 'INFO - all clear', 'username': 'carol'})
    styles = app.highlight_hygiene_risk(row)
    assert '7DD3FC' in styles[0]


# ---------------------------------------------------------------------------
# safe_load_csv
# ---------------------------------------------------------------------------
def test_safe_load_csv_missing_file_returns_none():
    assert app.safe_load_csv('/nonexistent/path/report.csv', pd) is None


def test_safe_load_csv_empty_file_returns_none(tmp_path):
    empty_csv = tmp_path / 'empty.csv'
    empty_csv.write_text('col1,col2\n')  # header only, no rows
    assert app.safe_load_csv(str(empty_csv), pd) is None


def test_safe_load_csv_valid_file_returns_dataframe(tmp_path):
    csv_path = tmp_path / 'data.csv'
    csv_path.write_text('username,risk\nalice,HIGH\nbob,LOW\n')
    df = app.safe_load_csv(str(csv_path), pd)
    assert df is not None
    assert len(df) == 2
    assert list(df.columns) == ['username', 'risk']


def test_safe_load_csv_corrupt_file_returns_none_not_crash(tmp_path):
    """DAY 3 — a malformed CSV must degrade gracefully, never raise."""
    bad_csv = tmp_path / 'corrupt.csv'
    bad_csv.write_bytes(b'\x00\x01\x02not,valid,csv\xff\xfe')
    result = app.safe_load_csv(str(bad_csv), pd)
    assert result is None or isinstance(result, pd.DataFrame)


# ---------------------------------------------------------------------------
# generate_pdf_report
# ---------------------------------------------------------------------------
def test_generate_pdf_report_returns_bytes(events_df):
    pdf_bytes = app.generate_pdf_report(events_df, "Test Report", "2026-08-01", "2026-08-31")
    assert isinstance(pdf_bytes, (bytes, bytearray))
    assert pdf_bytes[:4] == b'%PDF'  # valid PDF file signature


def test_generate_pdf_report_handles_missing_columns_gracefully():
    """DAY 3 — if the DataFrame doesn't match IAM_EVENT_SCHEMA, this must not
    crash the whole app; it should degrade to None."""
    weird_df = pd.DataFrame([{"unexpected_col": "value"}])
    result = app.generate_pdf_report(weird_df, "Weird Report", "2026-08-01", "2026-08-31")
    assert result is None or isinstance(result, (bytes, bytearray))
