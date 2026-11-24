import pytest

from heap import MinHeap


def test_empty_heap():
    heap = MinHeap()
    assert len(heap) == 0
    assert heap.is_empty()
    assert "missing" not in heap
    with pytest.raises(IndexError):
        heap.peek()
    with pytest.raises(IndexError):
        heap.pop_min()


def test_push_pop_in_priority_order():
    heap = MinHeap()
    heap.push(5, "five")
    heap.push(1, "one")
    heap.push(3, "three")

    assert len(heap) == 3
    assert heap.peek() == (1, "one")
    assert heap.pop_min() == (1, "one")
    assert heap.pop_min() == (3, "three")
    assert heap.pop_min() == (5, "five")


def test_push_duplicate_rejected():
    heap = MinHeap()
    heap.push(2, "a")
    with pytest.raises(ValueError, match="already in heap"):
        heap.push(1, "a")


def test_membership_and_position_tracking():
    heap = MinHeap()
    heap.push(4, "d")
    heap.push(2, "b")
    heap.push(3, "c")

    assert "b" in heap
    assert "missing" not in heap
    assert heap._pos["b"] == 0
    heap.pop_min()
    assert "b" not in heap


def test_decrease_key_moves_element_to_front():
    heap = MinHeap()
    heap.push(8, "a")
    heap.push(5, "b")
    heap.push(3, "c")

    heap.decrease_key("a", 1)
    assert heap.peek() == (1, "a")
    assert heap._pos["a"] == 0


def test_decrease_key_missing_element():
    heap = MinHeap()
    with pytest.raises(KeyError):
        heap.decrease_key("missing", 1)


def test_decrease_key_rejects_higher_priority():
    heap = MinHeap()
    heap.push(2, "a")
    with pytest.raises(ValueError, match="higher"):
        heap.decrease_key("a", 3)


def test_equal_priority_update():
    heap = MinHeap()
    heap.push(2, "a")
    heap.decrease_key("a", 2)
    assert heap.peek() == (2, "a")


def test_large_mixed_heap_operations():
    heap = MinHeap()
    values = list(range(100, 0, -1))
    for value in values:
        heap.push(value, str(value))

    heap.decrease_key("100", -1)
    assert heap.pop_min() == (-1, "100")

    remaining = [heap.pop_min()[0] for _ in range(len(heap))]
    assert remaining == sorted(v for v in values if v != 100)
