//! `std::sort` exactly as libc++ (LLVM 22, the one the reference
//! implementation was built with) performs it for element types that are
//! not arithmetic: introsort with median-of-3 / ninther pivots, insertion
//! sort below 24 elements and a heap-sort fallback.
//!
//! `std::sort` is not stable, so where the original sorts records by a key
//! that has duplicates, which of the equal records ends up last is decided
//! by this exact sequence of comparisons and moves. Reproducing the output
//! therefore needs the same algorithm, not just the same ordering.
//!
//! `less` must be a strict weak ordering. Indices below are positions the
//! algorithm computes itself, never values read from a file.

/// Sorts `v` like `std::sort(first, last, less)`.
pub fn sort_by<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    let n = v.len();
    if n == 0 {
        return;
    }
    let depth = 2 * (usize::BITS - 1 - n.leading_zeros()) as usize;
    introsort(v, 0, n, less, depth, true);
}

/// Sorts `v` like `std::partial_sort(first, last, last, less)` (heap sort).
pub fn heap_sort_by<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    make_heap(v, less);
    for n in (2..=v.len()).rev() {
        if let Some(heap) = v.get_mut(..n) {
            pop_heap(heap, less);
        }
    }
}

fn sort3<T: Copy>(v: &mut [T], x: usize, y: usize, z: usize, less: &impl Fn(&T, &T) -> bool) {
    if !less(&v[y], &v[x]) {
        if !less(&v[z], &v[y]) {
            return;
        }
        v.swap(y, z);
        if less(&v[y], &v[x]) {
            v.swap(x, y);
        }
        return;
    }
    if less(&v[z], &v[y]) {
        v.swap(x, z);
        return;
    }
    v.swap(x, y);
    if less(&v[z], &v[y]) {
        v.swap(y, z);
    }
}

fn sort4<T: Copy>(
    v: &mut [T],
    x1: usize,
    x2: usize,
    x3: usize,
    x4: usize,
    less: &impl Fn(&T, &T) -> bool,
) {
    sort3(v, x1, x2, x3, less);
    if less(&v[x4], &v[x3]) {
        v.swap(x3, x4);
        if less(&v[x3], &v[x2]) {
            v.swap(x2, x3);
            if less(&v[x2], &v[x1]) {
                v.swap(x1, x2);
            }
        }
    }
}

fn sort5<T: Copy>(v: &mut [T], x: [usize; 5], less: &impl Fn(&T, &T) -> bool) {
    let [x1, x2, x3, x4, x5] = x;
    sort4(v, x1, x2, x3, x4, less);
    if less(&v[x5], &v[x4]) {
        v.swap(x4, x5);
        if less(&v[x4], &v[x3]) {
            v.swap(x3, x4);
            if less(&v[x3], &v[x2]) {
                v.swap(x2, x3);
                if less(&v[x2], &v[x1]) {
                    v.swap(x1, x2);
                }
            }
        }
    }
}

/// Sorts ranges of up to five elements; false when the range is longer.
fn sort_small<T: Copy>(
    v: &mut [T],
    first: usize,
    last: usize,
    less: &impl Fn(&T, &T) -> bool,
) -> bool {
    match last - first {
        0 | 1 => {}
        2 => {
            if less(&v[last - 1], &v[first]) {
                v.swap(first, last - 1);
            }
        }
        3 => sort3(v, first, first + 1, last - 1, less),
        4 => sort4(v, first, first + 1, first + 2, last - 1, less),
        5 => sort5(v, [first, first + 1, first + 2, first + 3, last - 1], less),
        _ => return false,
    }
    true
}

/// Moves `v[i]` down into the sorted run before it. With `guard` the scan
/// stops at `first`; without, an element not greater than `v[i]` is assumed
/// to exist at or before `first - 1`.
fn insert_backwards<T: Copy>(
    v: &mut [T],
    first: usize,
    i: usize,
    guard: bool,
    less: &impl Fn(&T, &T) -> bool,
) {
    let t = v[i];
    let mut k = i - 1;
    let mut j = i;
    loop {
        v[j] = v[k];
        j = k;
        if (guard && j == first) || k == 0 {
            break;
        }
        k -= 1;
        if !less(&t, &v[k]) {
            break;
        }
    }
    v[j] = t;
}

fn insertion_sort<T: Copy>(
    v: &mut [T],
    first: usize,
    last: usize,
    guard: bool,
    less: &impl Fn(&T, &T) -> bool,
) {
    for i in first + 1..last {
        if less(&v[i], &v[i - 1]) {
            insert_backwards(v, first, i, guard, less);
        }
    }
}

/// Insertion sort that gives up after eight insertions; true when the range
/// ended up sorted.
fn insertion_sort_incomplete<T: Copy>(
    v: &mut [T],
    first: usize,
    last: usize,
    less: &impl Fn(&T, &T) -> bool,
) -> bool {
    if sort_small(v, first, last, less) {
        return true;
    }
    sort3(v, first, first + 1, first + 2, less);
    const LIMIT: u32 = 8;
    let mut count = 0;
    for i in first + 3..last {
        if less(&v[i], &v[i - 1]) {
            insert_backwards(v, first, i, true, less);
            count += 1;
            if count == LIMIT {
                return i + 1 == last;
            }
        }
    }
    true
}

/// Partitions around `v[first]`; elements equal to the pivot go right.
/// Returns the pivot's final position and whether no swap was needed.
fn partition_with_equals_on_right<T: Copy>(
    v: &mut [T],
    begin: usize,
    end: usize,
    less: &impl Fn(&T, &T) -> bool,
) -> (usize, bool) {
    let pivot = v[begin];
    let (mut first, mut last) = (begin, end);
    loop {
        first += 1;
        if !less(&v[first], &pivot) {
            break;
        }
    }
    if begin == first - 1 {
        while first < last {
            last -= 1;
            if less(&v[last], &pivot) {
                break;
            }
        }
    } else {
        loop {
            last -= 1;
            if less(&v[last], &pivot) {
                break;
            }
        }
    }
    let already_partitioned = first >= last;
    while first < last {
        v.swap(first, last);
        loop {
            first += 1;
            if !less(&v[first], &pivot) {
                break;
            }
        }
        loop {
            last -= 1;
            if less(&v[last], &pivot) {
                break;
            }
        }
    }
    let pivot_pos = first - 1;
    if begin != pivot_pos {
        v[begin] = v[pivot_pos];
    }
    v[pivot_pos] = pivot;
    (pivot_pos, already_partitioned)
}

/// Partitions around `v[first]`; elements equal to the pivot go left.
/// Returns the start of the right part.
fn partition_with_equals_on_left<T: Copy>(
    v: &mut [T],
    begin: usize,
    end: usize,
    less: &impl Fn(&T, &T) -> bool,
) -> usize {
    let pivot = v[begin];
    let (mut first, mut last) = (begin, end);
    if less(&pivot, &v[last - 1]) {
        loop {
            first += 1;
            if less(&pivot, &v[first]) {
                break;
            }
        }
    } else {
        loop {
            first += 1;
            if !(first < last && !less(&pivot, &v[first])) {
                break;
            }
        }
    }
    if first < last {
        loop {
            last -= 1;
            if !less(&pivot, &v[last]) {
                break;
            }
        }
    }
    while first < last {
        v.swap(first, last);
        loop {
            first += 1;
            if less(&pivot, &v[first]) {
                break;
            }
        }
        loop {
            last -= 1;
            if !less(&pivot, &v[last]) {
                break;
            }
        }
    }
    let pivot_pos = first - 1;
    if begin != pivot_pos {
        v[begin] = v[pivot_pos];
    }
    v[pivot_pos] = pivot;
    first
}

fn introsort<T: Copy>(
    v: &mut [T],
    mut first: usize,
    mut last: usize,
    less: &impl Fn(&T, &T) -> bool,
    mut depth: usize,
    mut leftmost: bool,
) {
    const LIMIT: usize = 24;
    const NINTHER_THRESHOLD: usize = 128;
    loop {
        let len = last - first;
        if sort_small(v, first, last, less) {
            return;
        }
        if len < LIMIT {
            insertion_sort(v, first, last, leftmost, less);
            return;
        }
        if depth == 0 {
            if let Some(range) = v.get_mut(first..last) {
                heap_sort_by(range, less);
            }
            return;
        }
        depth -= 1;
        let half = len / 2;
        if len > NINTHER_THRESHOLD {
            sort3(v, first, first + half, last - 1, less);
            sort3(v, first + 1, first + half - 1, last - 2, less);
            sort3(v, first + 2, first + half + 1, last - 3, less);
            sort3(v, first + half - 1, first + half, first + half + 1, less);
            v.swap(first, first + half);
        } else {
            sort3(v, first + half, first, last - 1, less);
        }
        if !leftmost && !less(&v[first - 1], &v[first]) {
            first = partition_with_equals_on_left(v, first, last, less);
            continue;
        }
        let (pivot, already_partitioned) = partition_with_equals_on_right(v, first, last, less);
        if already_partitioned {
            let left_sorted = insertion_sort_incomplete(v, first, pivot, less);
            if insertion_sort_incomplete(v, pivot + 1, last, less) {
                if left_sorted {
                    return;
                }
                last = pivot;
                continue;
            } else if left_sorted {
                first = pivot + 1;
                continue;
            }
        }
        introsort(v, first, pivot, less, depth, leftmost);
        leftmost = false;
        first = pivot + 1;
    }
}

fn sift_down<T: Copy>(v: &mut [T], mut start: usize, less: &impl Fn(&T, &T) -> bool) {
    let len = v.len();
    if len < 2 || (len - 2) / 2 < start {
        return;
    }
    let pick = |v: &[T], parent: usize| {
        let child = 2 * parent + 1;
        if child + 1 < len && less(&v[child], &v[child + 1]) {
            child + 1
        } else {
            child
        }
    };
    let mut child = pick(v, start);
    if less(&v[child], &v[start]) {
        return;
    }
    let top = v[start];
    loop {
        v[start] = v[child];
        start = child;
        if (len - 2) / 2 < child {
            break;
        }
        child = pick(v, child);
        if less(&v[child], &top) {
            break;
        }
    }
    v[start] = top;
}

fn make_heap<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    let n = v.len();
    if n > 1 {
        for start in (0..=(n - 2) / 2).rev() {
            sift_down(v, start, less);
        }
    }
}

/// Moves the hole at the root down to a leaf along the larger children and
/// returns its position.
fn floyd_sift_down<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) -> usize {
    let len = v.len();
    let mut hole = 0;
    loop {
        let mut child = 2 * hole + 1;
        if child + 1 < len && less(&v[child], &v[child + 1]) {
            child += 1;
        }
        v[hole] = v[child];
        hole = child;
        if hole > (len - 2) / 2 {
            return hole;
        }
    }
}

/// Restores the heap after `v[end - 1]` was appended to the heap
/// `v[..end - 1]`.
fn sift_up<T: Copy>(v: &mut [T], end: usize, less: &impl Fn(&T, &T) -> bool) {
    if end < 2 {
        return;
    }
    let mut last = end - 1;
    let mut parent = (end - 2) / 2;
    if less(&v[parent], &v[last]) {
        let t = v[last];
        loop {
            v[last] = v[parent];
            last = parent;
            if parent == 0 {
                break;
            }
            parent = (parent - 1) / 2;
            if !less(&v[parent], &t) {
                break;
            }
        }
        v[last] = t;
    }
}

/// Moves the largest element of the heap `v` to its end.
fn pop_heap<T: Copy>(v: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    let len = v.len();
    if len < 2 {
        return;
    }
    let top = v[0];
    let hole = floyd_sift_down(v, less);
    let last = len - 1;
    if hole == last {
        v[hole] = top;
    } else {
        v[hole] = v[last];
        v[last] = top;
        sift_up(v, hole + 1, less);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic input: `n` records with keys below `modulus`, tagged
    /// with their original position.
    fn input(n: usize, modulus: u64, seed: u64) -> Vec<(u64, u32)> {
        let mut state = seed;
        (0..n)
            .map(|i| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((state >> 33) % modulus, i as u32)
            })
            .collect()
    }

    /// FNV-1a over the original positions in their final order.
    fn fingerprint(v: &[(u64, u32)]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for (_, i) in v {
            for b in i.to_le_bytes() {
                h = (h ^ b as u64).wrapping_mul(0x100000001b3);
            }
        }
        h
    }

    fn less(a: &(u64, u32), b: &(u64, u32)) -> bool {
        a.0 < b.0
    }

    fn assert_sorted_permutation(v: &[(u64, u32)], n: usize) {
        assert!(v.windows(2).all(|w| w[0].0 <= w[1].0));
        let mut seen: Vec<u32> = v.iter().map(|e| e.1).collect();
        seen.sort_unstable();
        assert!(seen.iter().copied().eq(0..n as u32));
    }

    #[test]
    fn sorts_every_shape() {
        for n in (0..200).chain([255, 256, 257, 1000, 4097]) {
            for modulus in [1, 2, 3, 7, 50, 1 << 40] {
                let mut v = input(n, modulus, n as u64 * 31 + modulus);
                sort_by(&mut v, &less);
                assert_sorted_permutation(&v, n);
                let mut h = input(n, modulus, n as u64 * 31 + modulus);
                heap_sort_by(&mut h, &less);
                assert_sorted_permutation(&h, n);
            }
        }
        // Already sorted, reversed and organ-pipe inputs.
        for n in [24, 100, 129, 5000] {
            let mut asc: Vec<(u64, u32)> = (0..n).map(|i| (i as u64 / 3, i as u32)).collect();
            sort_by(&mut asc, &less);
            assert_sorted_permutation(&asc, n);
            let mut desc: Vec<(u64, u32)> =
                (0..n).map(|i| ((n - i) as u64 / 3, i as u32)).collect();
            sort_by(&mut desc, &less);
            assert_sorted_permutation(&desc, n);
            let mut pipe: Vec<(u64, u32)> =
                (0..n).map(|i| (i.min(n - i) as u64, i as u32)).collect();
            sort_by(&mut pipe, &less);
            assert_sorted_permutation(&pipe, n);
        }
    }

    /// `(n, modulus, fingerprint after std::sort, after std::partial_sort)`
    /// produced by libc++ for `input(n, modulus, n * 31 + modulus)` sorted
    /// by key only (generator: `std::vector<std::pair<uint64_t,
    /// std::string>>`, Apple clang 21 / libc++ 22, `-O3`).
    #[rustfmt::skip]
    const LIBCXX: &[(usize, u64, u64, u64)] = &[
        (0, 1, 0xcbf29ce484222325, 0xcbf29ce484222325), (0, 2, 0xcbf29ce484222325, 0xcbf29ce484222325),
        (0, 5, 0xcbf29ce484222325, 0xcbf29ce484222325), (0, 50, 0xcbf29ce484222325, 0xcbf29ce484222325),
        (0, 1000, 0xcbf29ce484222325, 0xcbf29ce484222325), (0, 1099511627776, 0xcbf29ce484222325, 0xcbf29ce484222325),
        (1, 1, 0x4d25767f9dce13f5, 0x4d25767f9dce13f5), (1, 2, 0x4d25767f9dce13f5, 0x4d25767f9dce13f5),
        (1, 5, 0x4d25767f9dce13f5, 0x4d25767f9dce13f5), (1, 50, 0x4d25767f9dce13f5, 0x4d25767f9dce13f5),
        (1, 1000, 0x4d25767f9dce13f5, 0x4d25767f9dce13f5), (1, 1099511627776, 0x4d25767f9dce13f5, 0x4d25767f9dce13f5),
        (2, 1, 0x08cd4c29d1e47d34, 0x08cd4c29d1e47d34), (2, 2, 0x89cd31291d2aefa4, 0x89cd31291d2aefa4),
        (2, 5, 0x89cd31291d2aefa4, 0x89cd31291d2aefa4), (2, 50, 0x89cd31291d2aefa4, 0x89cd31291d2aefa4),
        (2, 1000, 0x89cd31291d2aefa4, 0x89cd31291d2aefa4), (2, 1099511627776, 0x08cd4c29d1e47d34, 0x08cd4c29d1e47d34),
        (3, 1, 0x756241e1be8c9396, 0x9ef40c127c771966), (3, 2, 0x9f19854a6eada506, 0x9f19854a6eada506),
        (3, 5, 0x756241e1be8c9396, 0x756241e1be8c9396), (3, 50, 0x9ef40c127c771966, 0x9ef40c127c771966),
        (3, 1000, 0xf26292e3dcb93c46, 0xf26292e3dcb93c46), (3, 1099511627776, 0x9f19854a6eada506, 0x9f19854a6eada506),
        (4, 1, 0x30d77e22c5da0365, 0x6726d83826048e35), (4, 2, 0x6726d83826048e35, 0x6726d83826048e35),
        (4, 5, 0x04ae4a28f8977365, 0x04ae4a28f8977365), (4, 50, 0x654c877181ae34f5, 0x654c877181ae34f5),
        (4, 1000, 0xdaf706c0487661f5, 0xdaf706c0487661f5), (4, 1099511627776, 0x90de1ba0d6259fa5, 0x90de1ba0d6259fa5),
        (5, 1, 0xeb29754b740c25f1, 0xb7f1a88fd8409321), (5, 2, 0x354cb02171cf2191, 0xe1a8ebf88861a491),
        (5, 5, 0x57facf315ee9c561, 0x0b6ff380cf778481), (5, 50, 0xdaaa175650cd7041, 0xdaaa175650cd7041),
        (5, 1000, 0x8e6fa27eb14adbd1, 0x8e6fa27eb14adbd1), (5, 1099511627776, 0x0a3b3f82d25ea4b1, 0x0a3b3f82d25ea4b1),
        (6, 1, 0xac6313d97a44af34, 0x2645cfb51c80b754), (6, 2, 0xeb8dd2a9c3a5ac24, 0xe8e9b76d91958144),
        (6, 5, 0x63c62917c92e22c4, 0xbe68c1e2ea2fd414), (6, 50, 0x96c8b87bdbce5b74, 0x96c8b87bdbce5b74),
        (6, 1000, 0x67b2e9285be6e384, 0x67b2e9285be6e384), (6, 1099511627776, 0xba336961406d2064, 0xba336961406d2064),
        (7, 1, 0xae7a689bc2e9f352, 0xaa0db73b8c93a172), (7, 2, 0x4eb737f0c2298122, 0x468ed3f744302372),
        (7, 5, 0x822cf87f07a54ef2, 0x73908e596dcf41b2), (7, 50, 0x082f045df6483982, 0xe81842e05ff41c52),
        (7, 1000, 0x545926e6cd0b2c32, 0x545926e6cd0b2c32), (7, 1099511627776, 0x99c7964427c95c62, 0x99c7964427c95c62),
        (8, 1, 0x66b04c3323ce3f25, 0x413bde6cc5695f45), (8, 2, 0x1de1fa706a328735, 0x243fc553dbe16bf5),
        (8, 5, 0x9407e770afe21a85, 0x9407e770afe21a85), (8, 50, 0xf0eee9e5d0b9f395, 0xf0eee9e5d0b9f395),
        (8, 1000, 0x4dec5b54dfaae695, 0x4dec5b54dfaae695), (8, 1099511627776, 0x734a383efd888475, 0x734a383efd888475),
        (9, 1, 0xec449f96f087d47d, 0xc128b6df3557f1cd), (9, 2, 0x5915f97cdb6573ed, 0xc99ee4a7fb90fa8d),
        (9, 5, 0xaa7f8f532aad5fcd, 0x80c84bea7a8c4e5d), (9, 50, 0xbdda62eacd267f9d, 0x76bdc28e02c66d5d),
        (9, 1000, 0xc2a9aafaa795f8ed, 0xc2a9aafaa795f8ed), (9, 1099511627776, 0x1fc378be89efd8cd, 0x1fc378be89efd8cd),
        (10, 1, 0x43633e3ff0f885b4, 0x39d3d83365326b94), (10, 2, 0x38b8b68588c09364, 0x73be0d388d984344),
        (10, 5, 0x380051c7734432f4, 0x95d3215e02feb9a4), (10, 50, 0x5400919b99b9d134, 0x5400919b99b9d134),
        (10, 1000, 0xb2bee90e90d9ca94, 0xb2bee90e90d9ca94), (10, 1099511627776, 0xb4471e690e2e3bd4, 0xb4471e690e2e3bd4),
        (11, 1, 0x8a496d7f8351489e, 0x90680fd52968a70e), (11, 2, 0x064493d766c3803e, 0x85c4c05bab551cde),
        (11, 5, 0xbea2a0648560ac5e, 0xf35224d8912c8bbe), (11, 50, 0x5561807b3417749e, 0xfcfb13bcb38e57ee),
        (11, 1000, 0x55747970af03978e, 0x55747970af03978e), (11, 1099511627776, 0x31a97523a6b8734e, 0x31a97523a6b8734e),
        (12, 1, 0xe554888727308865, 0x761c431ef4603b35), (12, 2, 0xf365f33197435b75, 0x35a3090f2acf25d5),
        (12, 5, 0x424a58f96cc30cb5, 0xd32c5ba6353fb265), (12, 50, 0x7cff87dcd96d7605, 0x6ff3c07707b189e5),
        (12, 1000, 0xf3b4a2a532f74a45, 0x5ad0da3135ff3375), (12, 1099511627776, 0xb3bcf6b6d18de3c5, 0xb3bcf6b6d18de3c5),
        (13, 1, 0xe6fecf7c5a675f79, 0xe798f00d308ec379), (13, 2, 0xc6145af24c025ec9, 0x9d1a8918d0b1b0a9),
        (13, 5, 0x5def28fe2199df39, 0x414a7a420df98d79), (13, 50, 0x04e2ea0c153f50a9, 0x04e2ea0c153f50a9),
        (13, 1000, 0xc43df680a81b0b99, 0xc43df680a81b0b99), (13, 1099511627776, 0xc6cc8d1c614278a9, 0xc6cc8d1c614278a9),
        (16, 1, 0x2135120b48416d25, 0xe6e737ead0a6e865), (16, 2, 0xed6dba856ac4a0c5, 0x29e19d0cb6f5cee5),
        (16, 5, 0x9ebdc32e3187b975, 0x3b2d62e92dc93565), (16, 50, 0x28bf6526c872eac5, 0xa7bf80277d2c7855),
        (16, 1000, 0x4bbf5d57adda2405, 0x4bbf5d57adda2405), (16, 1099511627776, 0x5d8a4076bb612845, 0x5d8a4076bb612845),
        (20, 1, 0x180afee825580385, 0xf5122167eb0f2a55), (20, 2, 0x39b51d1fc8c825a5, 0xee51194bb3ed4275),
        (20, 5, 0x9f9f3a9bca1b5b55, 0x00be11428be0ff55), (20, 50, 0x771ff54498660355, 0xb4cde3990d413bd5),
        (20, 1000, 0x5007ad1881214c65, 0x5007ad1881214c65), (20, 1099511627776, 0x9deb6da3aea3d175, 0x9deb6da3aea3d175),
        (23, 1, 0xe5111f76ab4b6d82, 0x433f69448fa2cd42), (23, 2, 0x4d72a655013e0cb2, 0x6ed5b54fdb72cdb2),
        (23, 5, 0x746b82ad4b5c6902, 0xb06bd89f987da982), (23, 50, 0xd3c0e917fec66572, 0xb6eed8779093b2c2),
        (23, 1000, 0x082641b6072e0f42, 0x082641b6072e0f42), (23, 1099511627776, 0x46ab0358294a0512, 0x46ab0358294a0512),
        (24, 1, 0x49684e18280b7d65, 0x556fd184978899e5), (24, 2, 0x2ffd344a9311db95, 0x3e23c87519e401e5),
        (24, 5, 0xd73cbfafb4e3ff25, 0x36d24e1849347435), (24, 50, 0xe88f6910db8a0a05, 0xfbe393af4b6ed725),
        (24, 1000, 0xe116cbabeef07c85, 0xe116cbabeef07c85), (24, 1099511627776, 0x6bb8ebc22cf1f6a5, 0x6bb8ebc22cf1f6a5),
        (25, 1, 0x9da00788178adfcd, 0xc091d17bd5dff64d), (25, 2, 0x5c01ffe4bde902fd, 0xa89e098996a2ccfd),
        (25, 5, 0x1305d92897b4508d, 0x64a1b1fc350fa9ed), (25, 50, 0x06534a76052b9e0d, 0x2d9bef1d8599b9ad),
        (25, 1000, 0x01faf3063e232f6d, 0x01faf3063e232f6d), (25, 1099511627776, 0x83503e850a664ddd, 0x83503e850a664ddd),
        (30, 1, 0x95e32fde1ffdfc34, 0xbf13adc69ce459b4), (30, 2, 0x828b7dcd8e7601a4, 0x21e3d4cb52b3ca14),
        (30, 5, 0xbf31383aa070a524, 0x32100a37b0ffb764), (30, 50, 0xf4a3bba7d733f344, 0xc224989b0b6aef74),
        (30, 1000, 0x12944a1dba99c314, 0x12944a1dba99c314), (30, 1099511627776, 0x67166c658aabed94, 0x67166c658aabed94),
        (31, 1, 0x40f147e9f4bcabca, 0x2c2427c25d30754a), (31, 2, 0x8dd6f55d40577a1a, 0x9a83196114e46f0a),
        (31, 5, 0x0a441ec4a390493a, 0xa57ecaeaae57b2da), (31, 50, 0xb14dd240a09b4e5a, 0xd60f779f5829e0aa),
        (31, 1000, 0xcd9153b0dba25b3a, 0xcd9153b0dba25b3a), (31, 1099511627776, 0x81c74933d10a147a, 0x81c74933d10a147a),
        (32, 1, 0xf77b12af4e26bfa5, 0xec939aa13735e125), (32, 2, 0x5c4d2af360c9ed55, 0xcb33129db84eab45),
        (32, 5, 0x007b953bc8a71a75, 0x68f956605a0e42b5), (32, 50, 0xdc3baa5a6af2b615, 0xfda6f65f29a5d9e5),
        (32, 1000, 0xb8466d20060b30f5, 0xb8466d20060b30f5), (32, 1099511627776, 0xe4cbf827cfb56be5, 0xe4cbf827cfb56be5),
        (33, 1, 0x6dbfdd340d212655, 0xf5c4b0a114c7e505), (33, 2, 0xc89cf91900dfcfc5, 0x94e0787c1ee12845),
        (33, 5, 0x0d76089d03696245, 0xc93966b373b8ec35), (33, 50, 0x8d54812eb0dce735, 0x61d5a051edb76d25),
        (33, 1000, 0xdf83a23e47fb6bf5, 0x96cefb4edd895fa5), (33, 1099511627776, 0x21db7275b19e1c45, 0x21db7275b19e1c45),
        (47, 1, 0x13b596d4fac8e4fa, 0x080a4f4a95e4997a), (47, 2, 0x14f3e73b3dca8c1a, 0x76bc482c3c483f8a),
        (47, 5, 0x4347f9b2edf57d2a, 0x69b9ce396a4a06fa), (47, 50, 0xbe83afe3486e021a, 0xf405ea6cdd68d60a),
        (47, 1000, 0x8b691c7c57d0f70a, 0x8b691c7c57d0f70a), (47, 1099511627776, 0x5609f2056389785a, 0x5609f2056389785a),
        (48, 1, 0xddfe81ec81ef08a5, 0x8641845a2741f165), (48, 2, 0xa1448baf094dd065, 0x379223788689f6f5),
        (48, 5, 0x4f0056b5052f6435, 0x63d2f4597e3c9f55), (48, 50, 0x9f902d5ef10e17c5, 0xf14866881f7cc145),
        (48, 1000, 0x149495e8a6c8cb95, 0x149495e8a6c8cb95), (48, 1099511627776, 0xd34366c861382535, 0xd34366c861382535),
        (64, 1, 0xf5f45328a8ebdb25, 0x165b8b097d5def05), (64, 2, 0x4216a9f587123315, 0x7988086e18241bc5),
        (64, 5, 0xd6c794ada13e95b5, 0x840c4c726cafb335), (64, 50, 0x97a2c81489b39045, 0x41e504379e55e765),
        (64, 1000, 0xcf6362d8712d6fd5, 0xdbc1345f5d1a8435), (64, 1099511627776, 0x7b37e150b284bc25, 0x7b37e150b284bc25),
        (100, 1, 0x3cea9f2d76102aa5, 0x4eb0d835fb9fe135), (100, 2, 0x8bbe9f214cbd6f35, 0x746382d5937bbfb5),
        (100, 5, 0xda09f1010e844915, 0xc5eff5c7fef020e5), (100, 50, 0xbdd047e14e66f465, 0xeb67ea7785b554c5),
        (100, 1000, 0x81f79a48fb0b9135, 0x018c838f8faf5d95), (100, 1099511627776, 0x10bd409d5cf4eed5, 0x10bd409d5cf4eed5),
        (127, 1, 0x7a0ef259907f2b2a, 0x473274a2d124ceca), (127, 2, 0x219c937428690b2a, 0xa826e3da2cbace8a),
        (127, 5, 0xe4337598a5d65dca, 0xd503a6b33e45c48a), (127, 50, 0xea8a2e451eaeca1a, 0x5d454bb845b2e0da),
        (127, 1000, 0x3269a6bdd2c8062a, 0x3269a6bdd2c8062a), (127, 1099511627776, 0xe8441ee52699584a, 0xe8441ee52699584a),
        (128, 1, 0x709f2462c272f725, 0xc4fd5d87171f0085), (128, 2, 0xf5ccd51b8db46f05, 0x27662d9d84edcc85),
        (128, 5, 0xf3cee793e4244805, 0xed9483f931bb9635), (128, 50, 0x9667d3dc2ff60025, 0x5582d94ca3413eb5),
        (128, 1000, 0x86d0103aef9e38a5, 0x4ef23b24dc2ee605), (128, 1099511627776, 0xc8275276c3b4aac5, 0xc8275276c3b4aac5),
        (129, 1, 0xca71b4adb6f57075, 0x445becd6c28c5405), (129, 2, 0xca84c485c49f05c5, 0x71ee74b65e6beba5),
        (129, 5, 0x3b481313319d68f5, 0xd3009a67f5eacff5), (129, 50, 0x342456bd74a0c955, 0x5f137614d3ad1745),
        (129, 1000, 0xc86d54ec64f8c725, 0x6853e4d6ca705355), (129, 1099511627776, 0x8a5c48f35e9e7f05, 0x8a5c48f35e9e7f05),
        (130, 1, 0x9cd6759b79b67a24, 0x550bcba24b6b86f4), (130, 2, 0xf0d5005326930d74, 0x0dced4aadb6ee494),
        (130, 5, 0xe99c45ba19c3e5f4, 0x38bf5660f801a4b4), (130, 50, 0x0b44d99bcbf505b4, 0x91fc7ce835b651a4),
        (130, 1000, 0x20caa3faa63cd564, 0x00d0bf34db27ba04), (130, 1099511627776, 0xc52835d7b55b6344, 0xc52835d7b55b6344),
        (200, 1, 0xb46e27cb5beae525, 0x0121c6a2b9bc5ee5), (200, 2, 0x9c7f42d5578c13c5, 0x03a0590f37d86a65),
        (200, 5, 0x2c9ee425fc8a74a5, 0xb7b08b58b1929915), (200, 50, 0xed2af933d24f0dd5, 0x92a8a4cf29a145c5),
        (200, 1000, 0x4b03cd39c7829f95, 0x413266024544ecb5), (200, 1099511627776, 0xdd0c95eb978f6f95, 0xdd0c95eb978f6f95),
        (257, 1, 0x2486848ba8bf614a, 0xae16c0ddc3fa134e), (257, 2, 0x323954b1d03594fa, 0x34d0320c6300369a),
        (257, 5, 0xbddb9aee3b0f88be, 0x098d69ef501a95ee), (257, 50, 0x875e56a17e3124ae, 0xfb59115fb814d9de),
        (257, 1000, 0x6a9d4b7280a6894e, 0xb38a0031af9b783e), (257, 1099511627776, 0x48eb723c42fc5a5a, 0x48eb723c42fc5a5a),
        (1000, 1, 0x189aac5a91828505, 0x4d14210113f39359), (1000, 2, 0x24d2958da6ceab81, 0x79904ca729a02639),
        (1000, 5, 0xdc536d78a6a3b809, 0x04f40b12b73c4fe5), (1000, 50, 0xd23d70388b4d2ff1, 0xbfce00ae83df46e5),
        (1000, 1000, 0x736424076f470ee5, 0xb49fb3283c794021), (1000, 1099511627776, 0x59fdfdc9ed9ccdd9, 0x59fdfdc9ed9ccdd9),
        (5000, 1, 0x4a92f1f53bb9f375, 0x9e50e1b6d17f7891), (5000, 2, 0x8d2e8b02ceed2d61, 0x1e39a11cfe3b6f7d),
        (5000, 5, 0x71cb2ca231945141, 0xd4a1974f43b2062d), (5000, 50, 0x747afad4424ad579, 0xbe91951b8f444ee1),
        (5000, 1000, 0x066395d771c1a945, 0x6c0b263b6eec44dd), (5000, 1099511627776, 0x6e4ba70b588eab95, 0x6e4ba70b588eab95),
        (20000, 1, 0xc1765b9cb8f52bc5, 0x0a558c9eb9ff0d41), (20000, 2, 0x429a25afd17ba07d, 0x1b357ee23e2f2d79),
        (20000, 5, 0xa8feddf645e660d9, 0x71f166bae5938fc9), (20000, 50, 0x35cda312595110c5, 0xbe5470a62ccffbc5),
        (20000, 1000, 0x26e33c4c06b24639, 0x28c2548eddb2ec49), (20000, 1099511627776, 0xb0824673bf90a011, 0xb0824673bf90a011),
    ];

    #[test]
    fn equal_keys_end_up_where_libcxx_puts_them() {
        for &(n, modulus, sorted, heap_sorted) in LIBCXX {
            let mut v = input(n, modulus, n as u64 * 31 + modulus);
            sort_by(&mut v, &less);
            assert_eq!(fingerprint(&v), sorted, "std::sort n={n} modulus={modulus}");
            let mut h = input(n, modulus, n as u64 * 31 + modulus);
            heap_sort_by(&mut h, &less);
            assert_eq!(
                fingerprint(&h),
                heap_sorted,
                "std::partial_sort n={n} modulus={modulus}"
            );
        }
    }
}
