from django.dispatch import Signal

notification_posted = Signal(
    providing_args=['notification', 'users', 'context'])
