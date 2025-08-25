import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..models.models import Transaction, TransactionType, Account, Category, Budget, BudgetHistory

logger = logging.getLogger(__name__)


class BudgetService:
    PERIODS = {"weekly", "monthly", "yearly"}

    @staticmethod
    def get_period_range(period: str, anchor: Optional[datetime] = None) -> Tuple[datetime, datetime]:
        """Return start and end datetime for the current period based on anchor time (UTC)."""
        if anchor is None:
            anchor = datetime.utcnow()
        period = (period or "monthly").lower()
        if period == "weekly":
            # Start on Monday 00:00 of the current week
            start = anchor - timedelta(days=anchor.weekday())
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=7) - timedelta(seconds=1)
        elif period == "yearly":
            start = anchor.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            end = anchor.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
        else:
            # monthly
            start = anchor.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            # next month start
            if start.month == 12:
                next_month_start = start.replace(year=start.year + 1, month=1)
            else:
                next_month_start = start.replace(month=start.month + 1)
            end = next_month_start - timedelta(seconds=1)
        return start, end

    @staticmethod
    def _transactions_base_query(session: Session, user_id: int, category_id: Optional[int], account_id: Optional[int]):
        q = session.query(Transaction).join(Account, Transaction.account_id == Account.id)
        q = q.filter(Account.user_id == user_id)
        if category_id:
            q = q.filter(Transaction.category_id == category_id)
        if account_id:
            q = q.filter(Transaction.account_id == account_id)
        return q

    @staticmethod
    def calculate_spent(session: Session, user_id: int, start: datetime, end: datetime,
                        category_id: Optional[int] = None, account_id: Optional[int] = None) -> float:
        """Calculate total EXPENSE amount for given constraints (inclusive range)."""
        q = BudgetService._transactions_base_query(session, user_id, category_id, account_id)
        total = (
            session.query(func.coalesce(func.sum(Transaction.amount), 0.0))
            .select_from(Transaction)
            .join(Account, Transaction.account_id == Account.id)
            .filter(Account.user_id == user_id)
            .filter(Transaction.transaction_type == TransactionType.EXPENSE)
            .filter(Transaction.value_date >= start)
            .filter(Transaction.value_date <= end)
        )
        if category_id:
            total = total.filter(Transaction.category_id == category_id)
        if account_id:
            total = total.filter(Transaction.account_id == account_id)
        result = total.scalar() or 0.0
        return float(result)

    @staticmethod
    def current_status(session: Session, budget: Budget, now: Optional[datetime] = None) -> Dict[str, Any]:
        if not now:
            now = datetime.utcnow()
        start, end = BudgetService.get_period_range(budget.period, now)
        # Use budget.start_date as lower bound if it is in the future
        if budget.start_date and budget.start_date > start:
            start = budget.start_date
        # If end_date set and earlier than computed end, cap it
        if budget.end_date and budget.end_date < end:
            end = budget.end_date

        spent = BudgetService.calculate_spent(
            session,
            user_id=budget.user_id,
            start=start,
            end=end,
            category_id=budget.category_id,
            account_id=budget.account_id,
        )

        # Rollover logic: fetch last history entry if within previous period boundary
        rollover_amount = 0.0
        if budget.rollover_enabled:
            hist = (
                session.query(BudgetHistory)
                .filter(BudgetHistory.budget_id == budget.id)
                .order_by(BudgetHistory.period_end.desc())
                .first()
            )
            if hist:
                # Only roll over positive remaining
                remaining_prev = max((hist.budget_amount + hist.rollover_amount) - hist.spent_amount, 0.0)
                rollover_amount = remaining_prev

        available = (budget.amount or 0.0) + rollover_amount
        percent = (spent / available * 100.0) if available > 0 else 0.0

        # Alert levels at 50, 80, 100
        alerts = {
            "threshold": budget.alert_threshold or 80.0,
            "gte_50": percent >= 50.0,
            "gte_80": percent >= 80.0,
            "gte_100": percent >= 100.0,
            "custom_exceeded": percent >= (budget.alert_threshold or 80.0)
        }

        return {
            "budget_id": budget.id,
            "user_id": budget.user_id,
            "category_id": budget.category_id,
            "account_id": budget.account_id,
            "period": budget.period,
            "period_start": start,
            "period_end": end,
            "amount": float(budget.amount or 0.0),
            "rollover": float(rollover_amount),
            "available": float(available),
            "spent": float(spent),
            "remaining": float(max(available - spent, 0.0)),
            "percent_used": float(percent),
            "is_active": bool(budget.is_active),
            "alerts": alerts,
        }

    @staticmethod
    def snapshot_history(session: Session, budget: Budget, now: Optional[datetime] = None) -> BudgetHistory:
        """Create or update a history snapshot for the current period."""
        status = BudgetService.current_status(session, budget, now)
        hist = BudgetHistory(
            budget_id=budget.id,
            period_start=status["period_start"],
            period_end=status["period_end"],
            spent_amount=status["spent"],
            budget_amount=status["amount"],
            rollover_amount=status["rollover"],
        )
        session.add(hist)
        session.commit()
        return hist

    @staticmethod
    def list_budgets_with_status(session: Session, user_id: int) -> List[Dict[str, Any]]:
        budgets = session.query(Budget).filter(Budget.user_id == user_id).order_by(Budget.created_at.desc()).all()
        return [BudgetService.current_status(session, b) for b in budgets]
