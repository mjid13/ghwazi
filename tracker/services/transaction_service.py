from ..models import Transaction


class TransactionService:
    """Business logic for Transaction interactions."""

    def add_transaction(self, description: str, amount: float) -> Transaction:
        """Create and persist a new transaction."""
        return Transaction.objects.create(description=description, amount=amount)

    def list_transactions(self):
        """Return all transactions ordered by creation time."""
        return Transaction.objects.order_by('-created_at')
