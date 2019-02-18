class ConfigFileReader(object):

    config_file = ""
    config_file_path = ""

    def __init__(self, path):
        self.set_config_file(path=path)
        self.read_config_file()

    def set_config_file(self, path):
        self.config_file_path = path

    def read_config_file(self):
        try:
            file = open(self.config_file_path)
            self.config_file = file.readlines()
            file.close()
        except FileNotFoundError:
            print("No configuration File found.")

    def get_value(self, key):
        finder = ValueFinder
        return finder.find_value_by_key(file=self.config_file, key=key)


class ValueFinder(object):

    def __init__(self):
        self.ASSIGNMENT_TOKEN = " = "
        self.SEPARATOR_TOKEN = "\n"

    def find_value_by_key(self, file, key):
        for line in file:
            if line.startswith(key):
                return self.extract_value(line, key)
        return ""

    def extract_value(self, line, key):
        return line\
            .replace(key, "")\
            .replace(self.ASSIGNMENT_TOKEN, "")\
            .replace(self.SEPARATOR_TOKEN, "")
