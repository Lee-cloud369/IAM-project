import app


# ---------------------------------------------------------------------------
# PrivilegeEscalationService
# ---------------------------------------------------------------------------
def test_privilege_escalation_metrics_counts(events_df):
    service = app.PrivilegeEscalationService(load_fn=lambda: events_df, pdf_fn=app.generate_pdf_report)
    rows = service.metrics(events_df)
    metrics = {label: value for label, value, _ in rows}

    assert metrics["Total Events"] == 4
    assert metrics["Critical"] == 1
    assert metrics["High"] == 1
    assert metrics["Medium"] == 1


def test_privilege_escalation_highlighter_matches_highlight_risk(events_df):
    service = app.PrivilegeEscalationService(load_fn=lambda: events_df, pdf_fn=app.generate_pdf_report)
    row = events_df.iloc[0]  # CRITICAL row
    assert service.highlighter(row) == app.highlight_risk(row)


# ---------------------------------------------------------------------------
# DriftAnalyzerService
# ---------------------------------------------------------------------------
def test_drift_analyzer_metrics_counts(drift_df):
    service = app.DriftAnalyzerService(load_fn=lambda: drift_df)
    rows = service.metrics(drift_df)
    metrics = {label: value for label, value, _ in rows}

    assert metrics["Unused Permissions"] == 1  # NEVER USED rows
    assert metrics["High Risk"] == 1
    assert metrics["Medium Risk"] == 1


# ---------------------------------------------------------------------------
# CredentialHygieneService
# ---------------------------------------------------------------------------
def test_credential_hygiene_metrics_counts(hygiene_df):
    service = app.CredentialHygieneService(load_fn=lambda: hygiene_df)
    rows = service.metrics(hygiene_df)
    metrics = {label: value for label, value, _ in rows}

    assert metrics["Users Without MFA"] == 1
    assert metrics["Keys Needing Rotation"] == 1  # "not rotated" in risk text


# ---------------------------------------------------------------------------
# Polymorphism guardrail — every service satisfies the common interface
# ---------------------------------------------------------------------------
def test_all_services_are_security_service_subclasses():
    for cls in (app.PrivilegeEscalationService, app.DriftAnalyzerService, app.CredentialHygieneService):
        assert issubclass(cls, app.SecurityService)


def test_empty_message_mentions_service_name(hygiene_df):
    service = app.CredentialHygieneService(load_fn=lambda: hygiene_df)
    assert service.name in service.empty_message()
