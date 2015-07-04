###############################################################################
## Imports
###############################################################################
# Python
from collections import Iterable
from importlib import import_module

# Django
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db import models
from django.db.models import Q
from django.db.models.signals import pre_delete
from django.dispatch import receiver
from django.utils.timezone import now

# User
from notifier import settings
from notifier import managers
from notifier import signals

User = get_user_model()


###############################################################################
## Models
###############################################################################
class BaseModel(models.Model):
    """Abstract base class with auto-populated created and updated fields. """
    created = models.DateTimeField(default=now, db_index=True)
    updated = models.DateTimeField(default=now, db_index=True)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        self.updated = now()
        super(BaseModel, self).save(*args, **kwargs)


class Backend(BaseModel):
    """
    Entries for various delivery backends (SMS, Email)
    """
    name = models.CharField(max_length=200, unique=True, db_index=True)
    display_name = models.CharField(max_length=200, null=True)
    description = models.CharField(max_length=500, null=True)

    # This can be set to False to stop all deliveries using this
    # method, regardless of permissions and preferences
    enabled = models.BooleanField(default=True)

    # The klass value defines the class to be used to send the notification.
    klass = models.CharField(
        max_length=500,
        help_text='Example: notifier.backends.EmailBackend')

    def __unicode__(self):
        return self.name

    def _get_backendclass(self):
        """
        Return the python class from the string value in `self.klass`
        """
        module, klass = self.klass.rsplit('.', 1)
        return getattr(import_module(module), klass)
    backendclass = property(_get_backendclass)

    def get_notify_mandatory(self, notification):
        try:
            bcfg = BackendConfiguration.objects.get(
                notification=notification, backend=self)
            return bcfg.notify_mandatory
        except BackendConfiguration.DoesNotExist:
            return False

    def send(self, user, notification, context=None):
        """
        Send the notification to the specified user using this backend.

        returns Boolean according to success of delivery.
        """

        backendobject = self.backendclass(notification)
        sent_success = backendobject.send(user, context)

        if settings.CREATE_SENT_NOTIFICATIONS:
            SentNotification.objects.create(
                user=user, notification=notification,
                backend=self, success=sent_success)

        return sent_success


class BackendConfiguration(BaseModel):
    """Configuration options per Notification, Backend"""
    class Meta:
        unique_together = ('backend', 'notification')

    backend = models.ForeignKey('Backend')
    notification = models.ForeignKey('Notification')

    notify_mandatory = models.BooleanField(default=False)
    notify_default = models.BooleanField(default=False)


class Notification(BaseModel):
    """
    Entries for various notifications
    """
    name = models.CharField(max_length=200, unique=True, db_index=True)
    display_name = models.CharField(max_length=200)
    description = models.CharField(max_length=500, null=True, blank=True)

    # This field determines whether the notification is to be shown
    #   to users or it is private and only set by code.
    # This only affects UI, the notification is otherwise enabled
    #   and usable in all ways.
    public = models.BooleanField(default=True)

    # user should have all the permissions selected here to be able to change
    # the user prefs for this notification or see it in the UI
    permissions = models.ManyToManyField(Permission, blank=True)

    # These are the backend methods that are allowed for this type of
    # notification
    backends = models.ManyToManyField(Backend, blank=True)

    objects = managers.NotificationManager()

    def __unicode__(self):
        return self.name

    def check_perms(self, user):
        # Need an iterable with permission strings to check using has_perms.
        # This makes it possible to take advantage of the cache.
        perm_list = set(
            ["%s.%s" % (p.content_type.app_label, p.codename)
             for p in self.permissions.select_related()]
        )

        if not user.has_perms(perm_list):
            return False
        return True

    def get_backends(self, user):
        """
        Returns backends after checking `User` and `Group` preferences
        as well as `backend.enabled` flag and any BackendConfiguration
        """
        backends_defaulting_to_true = set()
        backends_included_by_userprefs = set()
        backends_excluded_by_userprefs = set()
        backends_included_by_groupprefs = set()
        backends_excluded_by_groupprefs = set()
        backends_mandatory = set()

        # Process backend configuration for this notification to figure out
        # which backends are used by default and which are mandatory
        backend_configurations = BackendConfiguration.objects.filter(
            notification=self)
        for bcfg in backend_configurations:
            if bcfg.notify_default:
                backends_defaulting_to_true.add(bcfg.backend_id)
            if bcfg.notify_mandatory:
                backends_mandatory.add(bcfg.backend_id)

        # Figure out which are included/excluded by user preference
        user_backend_prefs = self.userprefs_set.filter(
            user=user).values('backend__id', 'notify')
        for bpref in user_backend_prefs:
            if bpref['notify']:
                backends_included_by_userprefs.add(bpref['backend__id'])
            else:
                backends_excluded_by_userprefs.add(bpref['backend__id'])

        # Figure out which are included/excluded by group preference
        group_backend_prefs = self.groupprefs_set.filter(
            group__in=user.groups.all()).values('backend__id', 'notify')
        for bpref in group_backend_prefs:
            if bpref['notify']:
                backends_included_by_groupprefs.add(bpref['backend__id'])
            else:
                backends_excluded_by_groupprefs.add(bpref['backend__id'])

        # Use sets to apply inclusions and then remove exclusions until
        # we end up with only those backends that are enabled for the user
        # for this notification.
        backend_ids = set()
        # Start with defaults that are true
        backend_ids = backend_ids.union(backends_defaulting_to_true)

        backend_ids = backend_ids.union(
            backends_included_by_groupprefs) - backends_excluded_by_groupprefs

        backend_ids = backend_ids.union(
            backends_included_by_userprefs) - backends_excluded_by_userprefs

        backend_ids = backend_ids.union(backends_mandatory)

        backends = self.backends.filter(
            enabled=True, pk__in=backend_ids)

        return backends

    def get_user_prefs(self, user):
        """
        Return a dictionary of all available backend methods with True
        or False values depending on preferences.
        """
        all_backends = self.backends.filter(enabled=True)
        selected_backends = self.get_backends(user)

        backend_dict = dict(zip(all_backends, [False] * len(all_backends)))
        for backend in all_backends:
            if backend in selected_backends:
                backend_dict[backend] = True

        return backend_dict

    def update_user_prefs(self, user, prefs_dict):
        """
        Update or create a `UserPrefs` instance as required
        """
        result = {}
        for backend, value in prefs_dict.items():
            if not isinstance(backend, Backend):
                backend = Backend.objects.get(name=backend)

            try:
                userpref = self.userprefs_set.get(
                    user=user,
                    backend=backend
                )
            except UserPrefs.DoesNotExist:
                UserPrefs.objects.create(
                    user=user,
                    notification=self,
                    backend=backend,
                    notify=value
                )
                result[backend.name] = 'created'
            else:
                if userpref.notify != value:
                    userpref.notify = value
                    userpref.save()
                    result[backend.name] = 'updated'
        return result

    def update_group_prefs(self, group, prefs_dict):
        """
        Update or create a `GroupPrefs` instance as required
        """
        result = {}
        for backend, value in prefs_dict.items():
            if not isinstance(backend, Backend):
                backend = Backend.objects.get(name=backend)

            try:
                grouppref = self.groupprefs_set.get(
                    group=group,
                    backend=backend
                )
            except GroupPrefs.DoesNotExist:
                GroupPrefs.objects.create(
                    group=group,
                    notification=self,
                    backend=backend,
                    notify=value
                )
                result[backend.name] = 'created'
            else:
                if grouppref.notify != value:
                    grouppref.notify = value
                    grouppref.save()
                    result[backend.name] = 'updated'
        return result

    def send(self, users, context=None):
        if not isinstance(users, Iterable):
            users = [users]

        try:
            for user in users:
                for backend in self.get_backends(user):
                    backend.send(user, self, context)
        finally:
            signals.notification_posted.send(sender=self.__class__,
                                             notification=self,
                                             users=users,
                                             context=context)


class GroupPrefs(BaseModel):
    """
    Per group notification settings

    If notification is not explicitly set to True, then default to False.
    """
    group = models.ForeignKey(Group)
    notification = models.ForeignKey(Notification)
    backend = models.ForeignKey(Backend)
    notify = models.BooleanField(default=True)

    class Meta:
        unique_together = ('group', 'notification', 'backend')

    def __unicode__(self):
        return '%s:%s:%s' % (self.group, self.notification, self.backend)


class UserPrefs(BaseModel):
    """
    Per user notification settings

    Supercedes group setting.
    If notification preference is not explicitly set, then use group setting.
    """
    user = models.ForeignKey(User)
    notification = models.ForeignKey(Notification)
    backend = models.ForeignKey(Backend)
    notify = models.BooleanField(default=True)

    objects = managers.UserPrefsManager()

    class Meta:
        unique_together = ('user', 'notification', 'backend')

    def __unicode__(self):
        return '%s:%s:%s' % (self.user, self.notification, self.backend)

    def save(self, *args, **kwargs):
        if not self.notification.check_perms(self.user):
            raise PermissionDenied
        super(UserPrefs, self).save(*args, **kwargs)


class SentNotification(BaseModel):
    """
    Record of every notification sent.
    """
    user = models.ForeignKey(User)
    notification = models.ForeignKey(Notification)
    backend = models.ForeignKey(Backend)
    success = models.BooleanField()
    read = models.BooleanField(default=False)

    def __unicode__(self):
        return '%s:%s:%s' % (self.user, self.notification, self.backend)


###############################################################################
## Signal Recievers
###############################################################################
@receiver(pre_delete, sender=Backend,
          dispatch_uid='notifier.models.backend_pre_delete')
def backend_pre_delete(sender, instance, **kwargs):
    raise PermissionDenied(
        'Cannot delete backend %s. Remove from settings.' % instance.name)
