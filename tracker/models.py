from django.db import models


class Transaction(models.Model):
    """Simple transaction model."""
    description = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.description} ({self.amount})"
