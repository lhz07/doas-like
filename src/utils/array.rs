use std::{mem::MaybeUninit, ops::Range};

pub struct Array<const N: usize, T> {
    data: [MaybeUninit<T>; N],
    len: usize,
}

impl<const N: usize, T> Array<N, T> {
    pub const fn new() -> Self {
        Self {
            // Safety: every element is uninit.
            data: unsafe { MaybeUninit::uninit().assume_init() },
            len: 0,
        }
    }

    pub const fn push(&mut self, val: T) {
        assert!(self.len < N, "array is full!");
        unsafe {
            self.data[self.len].as_mut_ptr().write(val);
        }
        self.len += 1;
    }

    pub const fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            unsafe { Some(self.data[self.len].as_mut_ptr().read()) }
        }
    }

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
            // Safety: every elements in out is None, and we have initialized data[i]
            unsafe {
                opt.write(Some(self.data[i].assume_init_read()));
            }
            i += 1;
        }
        out
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn as_slice(&self) -> &[T] {
        let data = unsafe { self.data.assume_init_ref() };
        slice(data, 0..self.len)
    }

    pub const fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe {
            core::slice::from_raw_parts_mut(self.data.assume_init_mut().as_mut_ptr(), self.len)
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }
}

pub const fn slice<T>(s: &[T], idx: Range<usize>) -> &[T] {
    if idx.start >= idx.end {
        unsafe {
            return core::slice::from_raw_parts(s.as_ptr(), 0);
        }
    }
    let len = idx.end - idx.start;
    unsafe { core::slice::from_raw_parts(&raw const s[idx.start], len) }
}

#[test]
fn const_array() {
    let a = const {
        let mut bytes = Array::<3, _>::new();
        bytes.push(4);
        bytes.push(5);
        bytes.push(6);
        bytes.clear();
        bytes.push(1);
        bytes.push(2);
        bytes.push(3);
        bytes.pop();
        let slice = bytes.as_slice();
        assert!(slice.len() == 2);
        assert!(bytes.len() == 2);
        bytes
    };
    let slice = [1, 2];
    assert_eq!(&slice, a.as_slice());
}
