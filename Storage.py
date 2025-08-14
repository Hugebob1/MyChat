import random
class Storage:
    def __init__(self):
        self.code = 0
        self.current_email = ""
        self.name = ""
        self.password = ""
    def set_code(self):
        self.code = random.randint(100000, 999999)
    def get_code(self):
        return self.code
    def set_current_email(self, email):
        self.current_email = email
    def get_current_email(self):
        return self.current_email
    def set_name(self, name):
        self.name = name
    def get_name(self):
        return self.name
    def set_password(self, password):
        self.password = password
    def get_password(self):
        return self.password
    def reset(self):
        self.code = 0
        self.current_email = ""
        self.name = ""
        self.password = ""