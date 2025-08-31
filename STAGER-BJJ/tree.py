class Node(object):
    def __init__(self):
        self.id = 0
        self.parent = -1
        self.childs = []
        self.addr = 0
        self.struct = None
        self.offset = 0
        self.bytes = None
        self.size = 0

    def __str__(self):
        result = str(self.id)

        return result