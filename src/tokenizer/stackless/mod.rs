pub mod parser;

use std::{
    cell::UnsafeCell,
    mem,
    pin::Pin,
    ptr,
    task::{Context, Poll},
};

pub struct Gen<'a, Y, F: Future> {
    state: Pin<&'a mut State<Y, F>>,
}

pub struct InitState<Y, F: Future>(mem::MaybeUninit<State<Y, F>>);

impl<Y, F: Future> InitState<Y, F> {
    pub fn new() -> Self {
        Self(mem::MaybeUninit::uninit())
    }
}

struct State<Y, F: Future> {
    val: Val<Y>,
    future: F,
}

#[derive(Debug)]
pub struct Val<Y> {
    yield_val: UnsafeCell<Option<Y>>,
}

impl<Y> Val<Y> {
    pub fn yield_(&self, val: Y) -> impl Future<Output = ()> {
        let yield_val = self.yield_val.get();
        unsafe {
            *yield_val = Some(val);
        }
        Yielded(&self.yield_val)
    }
}

struct Yielded<'a, Y>(&'a UnsafeCell<Option<Y>>);

impl<'a, Y> Future for Yielded<'a, Y> {
    type Output = ();
    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let val = self.0.get();
        // Safety: we are the unique visitor of ptr.
        if unsafe { (*val).is_some() } {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

impl<Y> Default for Val<Y> {
    fn default() -> Self {
        Self {
            yield_val: UnsafeCell::new(None),
        }
    }
}

impl<'a, Y, F: Future> Gen<'a, Y, F> {
    pub fn new(
        init_state: &'a mut InitState<Y, F>,
        producer: impl FnOnce(&'a Val<Y>) -> F,
    ) -> Self {
        let state = init_state.0.as_mut_ptr();
        // Safety: val is not initialized, write to it directly.
        unsafe {
            ptr::write(&raw mut (*state).val, Val::default());
        }
        // Safety: we just initialized val
        let future = unsafe { producer(&(*state).val) };
        // Safety: val is not initialized, write to it directly.
        unsafe {
            ptr::write(&raw mut (*state).future, future);
        }
        // Safety: we have initialized the state, and compiler guarantees state can not be moved.
        let state = unsafe { Pin::new_unchecked(init_state.0.assume_init_mut()) };
        Self { state }
    }

    pub fn next_impl(&mut self) -> Option<Y> {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let val;
        let future;
        // Safety: we just map the state to pinned future and immutable val.
        unsafe {
            let state = self.state.as_mut().get_unchecked_mut();
            future = Pin::new_unchecked(&mut state.future);
            val = &state.val;
        };
        match future.poll(&mut cx) {
            Poll::Pending => {
                let ptr = val.yield_val.get();
                // Safety: we are the unique visitor of ptr.
                unsafe { (*ptr).take() }
            }
            Poll::Ready(_) => None,
        }
    }
}

impl<'a, Y, F: Future> Iterator for Gen<'a, Y, F> {
    type Item = Y;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_impl()
    }
}

#[macro_export]
macro_rules! gen_iter {
    ($name:ident, $producer:expr) => {
        use $crate::tokenizer::stackless::*;
        let mut init = InitState::new();
        #[allow(unused_mut)]
        let mut $name = Gen::new(&mut init, $producer);
    };
}

#[macro_export]
macro_rules! gen_tokenizer {
    ($name:ident, $content:expr) => {
        use $crate::tokenizer::*;
        let mut init = InitState::new();
        let generator = Gen::new(&mut init, |co| parser::tokenizer(co, $content));
        #[allow(unused_mut)]
        let mut $name = $crate::tokenizer::Tokenizer::new(generator.peekable());
    };
}
