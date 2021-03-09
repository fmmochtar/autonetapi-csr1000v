from django.db import models

# Create your models here.

# Router model, now added default ACL ID and auto-mitigate functions
class Device(models.Model):
    ip_address = models.CharField(max_length=200)
    hostname = models.CharField(max_length=200)
    username = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    default_acl_id = models.CharField(max_length=128, default=False)
    auto_mitigate = models.BooleanField(null=False, default=False)

    def __str__(self):
        return "{} - {}".format(self.hostname, self.ip_address)

# Configurable ACL models
class AccessControlID(models.Model):
    acl_id = models.CharField(max_length=128)
    hostname = models.ForeignKey(Device, on_delete=models.CASCADE)

    def __str__(self):
        return "{} - {}".format(self.acl_id, self.hostname)

# This model is used to collect attacker source IP address
class Attacker(models.Model):
    source_ip = models.CharField(max_length=200)
    status = models.CharField(max_length=200)
    num_accumulated_attack = models.CharField(max_length=200)

    def __str__(self):
        return "{} - {}".format(self.source_ip, self.status)

# This model is used to contain collected attack logs
class AttackLog(models.Model):
    time = models.DateTimeField(null=True)
    source_ip = models.CharField(max_length=200)
    dest_port = models.CharField(max_length=200)
    conn_protocol = models.CharField(max_length=200)
    conn_flag = models.CharField(max_length=200)
    acl_id = models.CharField(max_length=200)
    acl_sequence = models.IntegerField()
    status = models.CharField(max_length=200)

    def __str__(self):
        return "{} - {} - {}".format(self.time, self.source_ip, self.status)

# This is for application log
class Log(models.Model):
    target = models.CharField(max_length=200)
    action = models.CharField(max_length=200)
    status = models.CharField(max_length=200)
    messages = models.CharField(max_length=255, blank=True)
    time = models.DateTimeField(null=True)
    user = models.CharField(max_length=200, default='Anonymous')

    def __str__(self):
        return "{} - {} - {}".format(self.target, self.action, self.status)