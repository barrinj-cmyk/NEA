class MinHeap:
    def __init__(self):
        self._heap = []   # list of (priority, element)
        self._pos = {}    # element -> index in self._heap

    # ---------- public interface ----------
    def __len__(self):
        return len(self._heap)

    def __contains__(self, element):
        return element in self._pos

    def is_empty(self):
        return len(self._heap) == 0

    def peek(self):
        #Return the minimum (priority, element) without removing it
        if self.is_empty():
            raise IndexError("peek from empty heap")
        return self._heap[0]

    def push(self, priority, element):
        if element in self._pos:
            raise ValueError(f"{element!r} already in heap; use decrease_key")
        self._heap.append((priority, element))
        index = len(self._heap) - 1
        self._pos[element] = index
        self._sift_up(index)

    def pop_min(self):
        #Remove and return the minimum (priority, element)
        if self.is_empty():
            raise IndexError("pop from empty heap")
        smallest = self._heap[0]
        last = self._heap.pop()
        del self._pos[smallest[1]]
        if self._heap:                      # heap not empty after removal
            self._heap[0] = last
            self._pos[last[1]] = 0
            self._sift_down(0)
        return smallest

    def decrease_key(self, element, new_priority):
        if element not in self._pos:
            raise KeyError(f"{element!r} not in heap")
        index = self._pos[element]
        if new_priority > self._heap[index][0]:
            raise ValueError("new priority is higher than current priority")
        self._heap[index] = (new_priority, element)
        self._sift_up(index)

    # ---------- internal helpers ----------
    @staticmethod
    def _parent(i):
        return (i - 1) // 2

    @staticmethod
    def _left(i):
        return 2 * i + 1

    @staticmethod
    def _right(i):
        return 2 * i + 2

    def _swap(self, i, j):
        self._heap[i], self._heap[j] = self._heap[j], self._heap[i]
        self._pos[self._heap[i][1]] = i
        self._pos[self._heap[j][1]] = j

    def _sift_up(self, i):
        while i > 0 and self._heap[i][0] < self._heap[self._parent(i)][0]:
            parent = self._parent(i)
            self._swap(i, parent)
            i = parent

    def _sift_down(self, i):
        size = len(self._heap)
        while True:
            smallest = i
            left, right = self._left(i), self._right(i)
            if left < size and self._heap[left][0] < self._heap[smallest][0]:
                smallest = left
            if right < size and self._heap[right][0] < self._heap[smallest][0]:
                smallest = right
            if smallest == i:
                return
            self._swap(i, smallest)
            i = smallest