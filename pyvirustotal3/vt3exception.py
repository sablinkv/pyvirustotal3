
class VT3Exception(Exception):
    def __init__(self, code, code_description, message):
        super().__init__(message)
        self.code = code
        self.code_description = code_description
        self.message = message

    def __str__(self):
        return f'{self.code_description}({self.code}): {self.message}.'