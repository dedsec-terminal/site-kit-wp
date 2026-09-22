import sys
sys.path.insert(0, "/home/user/django-audit-harness")
import srv_project  # configures settings
from django.core.management import execute_from_command_line
sys.argv = ["x", "runserver", "127.0.0.1:8765", "--noreload", "--nothreading"]
execute_from_command_line(sys.argv)
