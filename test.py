from collections.abc import MutableMapping


class Storage(MutableMapping):
    def __init__(self, *args, **kwargs):
        self._storage = dict()
        self.update(dict(*args, **kwargs))

    def __getitem__(self, key):
        return self._storage[key]

    def __setitem__(self, key, value):
        self._storage[key] = value

    def __delitem__(self, key):
        del self._storage[key]

    def __iter__(self):
        return iter(self._storage)

    def __len__(self):
        return len(self._storage)

    def __repr__(self):
        return f"{self.__class__.__name__}({self._storage})"

    def __str__(self):
        return str(self._storage)


s = Storage(my_key="my_value")
print(s["my_key"])
