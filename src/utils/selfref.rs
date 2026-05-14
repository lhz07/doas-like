use std::ops::Deref;

pub struct SelfRef<T, S> {
    data: T,
    _buf: S,
}

impl<T, S> SelfRef<T, S> {
    pub fn new(data: T, buf: S) -> Self {
        Self { data, _buf: buf }
    }
}

impl<T, S> Deref for SelfRef<T, S> {
    type Target = T;
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

impl<T: 'static + ?Sized> Deref for OwnedRef<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.data
    }
}
