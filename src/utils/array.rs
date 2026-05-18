use std::{mem::MaybeUninit, ops::Range};

/// A fixed-capacity array with manual initialization tracking.
///
/// Unlike `Vec`, this type can be fully used in `const` contexts.
///
/// ## Potential Memory Leak
///
/// This type intentionally does **not support automatic element
/// destruction in `const` contexts**, because current Rust const evaluation
/// does not allow executing destructor (drop glue) at the end of a const
/// evaluation.
///
/// If `T: Drop`, values stored in the array will not be automatically
/// dropped when the array goes out of scope in const code. You need to manually
/// call `clear()` or `drop()`.
pub struct Array<const N: usize, T> {
    data: [MaybeUninit<T>; N],
    len: usize,
}

impl<const N: usize, T> Array<N, T> {
    pub const fn new() -> Self {
        Self {
            // Safety: every element is `MaybeUninit`.
            data: unsafe { MaybeUninit::uninit().assume_init() },
            len: 0,
        }
    }

    /// Appends an element to the end of the array.
    ///
    /// Panics if the array is already full.
    pub const fn push(&mut self, val: T) {
        assert!(self.len < N, "array is full!");
        // Safety:
        // `self.len < N` guarantees the slot is in bounds and uninitialized.
        unsafe {
            self.data[self.len].as_mut_ptr().write(val);
        }
        self.len += 1;
    }

    pub const fn push_checked(&mut self, val: T) -> Result<(), T> {
        if self.len >= N {
            return Err(val);
        }
        // Safety:
        // `self.len < N` guarantees the slot is in bounds and uninitialized.
        unsafe {
            self.data[self.len].as_mut_ptr().write(val);
        }
        self.len += 1;
        Ok(())
    }

    pub const fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            // Safety:
            // - `data[self.len]` is initialized
            // - ownership is moved exactly once
            unsafe { Some(self.data[self.len].as_mut_ptr().read()) }
        }
    }

    /// Clears the array and returns all elements as `Option<T>`.
    ///
    /// This design is a **temporary workaround** for the lack of stable
    /// `const Drop` / `const Destruct` traits in Rust.
    ///
    /// Because we can not require `T` to satisfy `const Destruct`, so `drop_in_place` cannot
    /// currently be used here.
    ///
    /// we instead:
    /// - move out values using `assume_init_read`
    /// - return them as `Option<T>`
    /// - avoid destructor execution
    ///
    /// Once `const Destruct` becomes stable, this should be replaced with:
    /// `ptr::drop_in_place`-based implementation.
    pub const fn clear(&mut self) -> [Option<T>; N] {
        let mut out = [const { None }; N];
        if self.len == 0 {
            return out;
        }

        let mut i = 0;
        let len = self.len;
        self.len = 0;
        while i < len {
            let opt = &raw mut out[i];
            // Safety:
            // - `out[i]` is currently `None`
            // - `data[i]` is initialized
            // - each element is moved exactly once
            unsafe {
                opt.write(Some(self.data[i].assume_init_read()));
            }
            i += 1;
        }
        out
    }

    /// Drop the Array and its elements.
    pub fn drop(mut self) {
        let elems: *mut [T] = self.as_mut_slice();

        // SAFETY:
        // `elems` comes directly from `as_mut_slice` and is therefore valid.
        unsafe {
            std::ptr::drop_in_place(elems);
        }
    }

    /// Returns the number of initialized elements.
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a shared slice of initialized elements.
    pub const fn as_slice(&self) -> &[T] {
        // Safety:
        // Only the first `self.len` elements are exposed.
        // Those elements are guaranteed to be initialized.
        let data = unsafe { self.data.assume_init_ref() };
        slice(data, 0..self.len)
    }

    /// Returns a mutable slice of initialized elements.
    pub const fn as_mut_slice(&mut self) -> &mut [T] {
        // Safety:
        // Only the first `self.len` elements are exposed.
        // Those elements are guaranteed to be initialized.
        unsafe {
            core::slice::from_raw_parts_mut(self.data.assume_init_mut().as_mut_ptr(), self.len)
        }
    }

    pub const fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.data.as_mut_ptr().add(self.len) as *mut MaybeUninit<T>,
                self.capacity() - self.len,
            )
        }
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }
}

/// Returns a subslice for the given range.
///
/// This behaves similarly to standard slice indexing:
/// - panics if either bound is out of range
/// - panics if `start > end`
pub const fn slice<T>(s: &[T], idx: Range<usize>) -> &[T] {
    assert!(
        !(idx.start > s.len() || idx.end > s.len()),
        "index out of bounds"
    );
    assert!(idx.start <= idx.end, "slice start is greater than end");
    let len = idx.end - idx.start;

    // Safety: bounds are validated above
    unsafe { core::slice::from_raw_parts(s.as_ptr().add(idx.start), len) }
}

#[test]
fn const_array() {
    const {
        let mut a = Array::<3, i32>::new();

        a.push(1);
        a.push(2);
        a.push(3);

        let popped = a.pop();
        if let Some(3) = popped {
        } else {
            panic!("unexpected pop value");
        }

        let slice = a.as_slice();
        if slice.len() != 2 {
            panic!("unexpected len");
        }
        if slice[0] != 1 || slice[1] != 2 {
            panic!("unexpected slice content");
        }

        let cleared = a.clear();

        if let Some(1) = cleared[0]
            && let Some(2) = cleared[1]
            && cleared[2].is_none()
        {
        } else {
            panic!("unexpected clear result");
        }

        a.push(10);
        a.push(20);

        let s = a.as_mut_slice();
        if s.len() != 2 {
            panic!("unexpected slice len");
        }
        s[1] = 30;
        if s[0] != 10 || s[1] != 30 {
            panic!("unexpected slice values");
        }
    }
}

#[test]
fn const_slice_behavior() {
    const {
        let data = [1, 2, 3, 4];

        let a = slice(&data, 1..3);
        if a.len() != 2 || a[0] != 2 || a[1] != 3 {
            panic!("slice mismatch");
        }

        let b = slice(&data, 0..0);
        if !b.is_empty() {
            panic!("expected empty slice");
        }

        let c = slice(&data, 2..2);
        if !c.is_empty() {
            panic!("expected empty slice");
        }
    }
}

#[test]
fn drop_behavior() {
    use std::cell::RefCell;

    thread_local! {
        static NUM: RefCell<i32> = RefCell::new(10);
    }

    struct NeedDrop;
    impl Drop for NeedDrop {
        fn drop(&mut self) {
            NUM.with_borrow_mut(|n| {
                *n -= 1;
            });
        }
    }

    const ARRAY: Array<10, NeedDrop> = {
        let mut array = Array::<10, _>::new();
        let mut i = 0;
        while i < 10 {
            array.push(NeedDrop);
            i += 1;
        }
        array
    };

    NUM.with_borrow(|n| assert_eq!(*n, 10));
    ARRAY.drop();
    NUM.with_borrow(|n| assert_eq!(*n, 0));
}
