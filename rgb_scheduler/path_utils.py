import os


def get_project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_log_path(filename):
    return os.path.join(get_project_root(), "logs", filename)


def get_data_path(filename):
    return os.path.join(get_project_root(), "data", filename)


def get_static_path(filename):
    return os.path.join(get_project_root(), "static", filename)


def get_template_path():
    return os.path.join(get_project_root(), "templates")


def get_config_path(filename="config.ini"):
    return os.path.join(get_project_root(), filename)
