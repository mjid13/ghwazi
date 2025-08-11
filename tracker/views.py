from django.shortcuts import redirect, render

from .services.transaction_service import TransactionService


service = TransactionService()


def index(request):
    return render(request, 'tracker/index.html')


def transactions(request):
    if request.method == 'POST':
        description = request.POST.get('description', '')
        amount = request.POST.get('amount') or 0
        service.add_transaction(description, amount)
        return redirect('transactions')
    context = {'transactions': service.list_transactions()}
    return render(request, 'tracker/transactions.html', context)
