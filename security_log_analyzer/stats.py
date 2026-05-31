from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Iterable

from .models import CountItem, FailedLoginEvent, FailedLoginStats, LogRecord, SummaryData


HIGH_RISK_ACCOUNTS = {"root", "admin", "administrator", "sa", "oracle", "postgres", "mysql"}
LOGIN_LOG_TYPES = {"ssh_login", "system_login", "cloud_login"}


def generate_summary_data(records: Iterable[LogRecord]) -> SummaryData:
    record_list = list(records)
    ip_counter = Counter(record.ip for record in record_list if record.ip)
    account_counter = Counter(
        account
        for account in (record.account or record.username for record in record_list)
        if account
    )
    timestamps = [record.timestamp for record in record_list if record.timestamp is not None]

    top_ips = _to_count_items(ip_counter)
    top_accounts = _to_count_items(account_counter)
    high_risk_accounts = [
        item for item in top_accounts if item.key.lower() in HIGH_RISK_ACCOUNTS
    ]

    return SummaryData(
        total_events=len(record_list),
        success_events=sum(1 for record in record_list if record.succeeded is True),
        failure_events=sum(1 for record in record_list if record.succeeded is False),
        ip_count=len(ip_counter),
        account_count=len(account_counter),
        top_ips=top_ips,
        top_accounts=top_accounts,
        high_risk_accounts=high_risk_accounts,
        time_start=min(timestamps) if timestamps else None,
        time_end=max(timestamps) if timestamps else None,
    )


def count_failed_login(records: Iterable[LogRecord]) -> FailedLoginStats:
    failed_records = [
        record
        for record in records
        if record.succeeded is False and record.log_type in LOGIN_LOG_TYPES
    ]

    by_ip = _to_count_items(Counter(record.ip for record in failed_records if record.ip))
    by_account = _to_count_items(
        Counter(
            account
            for account in (record.account or record.username for record in failed_records)
            if account
        )
    )
    events = [
        FailedLoginEvent(
            time=record.timestamp,
            ip=record.ip,
            account=record.account or record.username,
            raw=record.raw,
            log_type=record.log_type,
        )
        for record in failed_records
    ]
    return FailedLoginStats(by_ip=by_ip, by_account=by_account, events=events)


def _to_count_items(counter: Counter[str]) -> list[CountItem]:
    return [CountItem(key=key, count=count) for key, count in counter.most_common()]
