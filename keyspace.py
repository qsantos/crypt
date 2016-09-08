#!/usr/bin/env python3
import itertools


class KeySpace:
    def __init__(self, pattern):
        parts = []
        pattern = iter(pattern)
        for c in pattern:
            if c == '\\':
                next_c = next(pattern)
                parts.append(next_c)
            elif c == '[':
                charset = []
                is_range = False
                for c in pattern:
                    if c == ']':
                        break
                    elif c == '\\':
                        c = next(pattern)
                    elif c == '-':
                        is_range = True
                        continue

                    if is_range:
                        is_range = False
                        start = ord(charset[-1])
                        stop = ord(c)
                        for i in range(start + 1, stop + 1):
                            charset.append(chr(i))
                    else:
                        charset.append(c)

                parts.append(''.join(charset))
            else:
                parts.append(c)
        self.parts = parts

    def __len__(self):
        p = 1
        for part in self.parts:
            p *= len(part)
        return p

    def __getitem__(self, index):
        def _(index):
            for part in reversed(self.parts):
                index, j = divmod(index, len(part))
                yield part[j]
            if index > 0:
                raise IndexError('Key index out of range')
        return ''.join(reversed(list(_(index))))

    def __iter__(self):
        for key in itertools.product(*self.parts):
            yield "".join(key)


if __name__ == '__main__':
    key_space = KeySpace('[0-9a-z]'*5)
    for key in key_space:
        print(key)
