use std::{ops::Deref, pin::Pin};

pub struct SelfRef<T: Deref, S> {
    data: Pin<T>,
    _buf: Pin<S>,
}

impl<T: Deref, S> SelfRef<T, S> {
    pub fn pin_new(data: T, buf: S) -> Self
    where
        <T as Deref>::Target: Unpin,
        S: Deref,
        <S as Deref>::Target: Unpin,
    {
        Self {
            data: Pin::new(data),
            _buf: Pin::new(buf),
        }
    }

    pub fn new(data: Pin<T>, buf: Pin<S>) -> Self {
        Self { data, _buf: buf }
    }
}

impl<T: Deref, S> Deref for SelfRef<T, S> {
    type Target = T::Target;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

pub struct OwnedRef<T: 'static + ?Sized> {
    data: &'static T,
}

impl<T: 'static + ?Sized> OwnedRef<T> {
    pub fn new(data: &'static T) -> Self {
        Self { data }
    }
}

impl<T: 'static + ?Sized> std::ops::Deref for OwnedRef<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.data
    }
}
