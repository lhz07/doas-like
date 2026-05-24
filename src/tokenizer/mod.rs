use std::{collections::HashSet, iter::Peekable, ops::Range, sync::LazyLock};

#[cfg(feature = "nightly")]
mod nightly;
#[cfg(feature = "nightly")]
pub use nightly::*;

#[cfg(not(feature = "nightly"))]
mod stackless;
#[cfg(not(feature = "nightly"))]
pub use stackless::*;

#[derive(Debug)]
pub enum State {
    Token(Token, usize),
    NewLine(usize, bool),
}

#[derive(Debug, Default)]
enum QuoteState {
    #[default]
    None,
    Half(usize),
    Full(Range<usize>),
}

impl QuoteState {
    fn take_option(&mut self) -> Option<Range<usize>> {
        match std::mem::take(self) {
            Self::None | Self::Half(_) => None,
            Self::Full(range) => Some(range),
        }
    }
}

#[derive(Debug, Default)]
pub struct Token {
    str: String,
    quoted: Option<Range<usize>>,
}

static KEYWORDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["permit", "deny", "as", "cmd", "args"]
        .into_iter()
        .collect()
});

impl Token {
    pub fn into_string(self) -> String {
        self.str
    }
    pub fn equal_key(&self, key: &str) -> bool {
        self.as_str() == key && !self.quoted()
    }
    pub fn is_key(&self) -> bool {
        !self.quoted() && KEYWORDS.contains(self.as_str())
    }
    pub fn as_str(&self) -> &str {
        &self.str
    }
    pub fn quoted(&self) -> bool {
        self.quoted.is_some()
    }
    pub fn quote_str(&self) -> Option<&str> {
        self.str.get(self.quoted.clone()?)
    }
    pub fn before_quoted(&self) -> &str {
        match self.quoted.clone() {
            Some(Range { start, .. }) => unsafe { self.str.get_unchecked(0..start) },
            None => &self.str,
        }
    }
    fn finish(&mut self, quote: Option<Range<usize>>) -> Self {
        self.quoted = quote;
        std::mem::take(self)
    }
}

pub struct Tokenizer<T>
where
    T: Iterator<Item = State>,
{
    tokenizer: Peekable<T>,
    line: usize,
    quoted: bool,
}

impl<T> Iterator for Tokenizer<T>
where
    T: Iterator<Item = State>,
{
    type Item = Token;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_impl()
    }
}

impl<T> Tokenizer<T>
where
    T: Iterator<Item = State>,
{
    pub fn new(tokenizer: Peekable<T>) -> Self {
        Self {
            tokenizer,
            line: 1,
            quoted: false,
        }
    }
    pub fn line(&self) -> usize {
        self.line
    }

    pub fn next_line(&mut self) -> Result<bool, usize> {
        if self.quoted {
            return Err(self.line);
        }
        Ok(self.peek().is_some())
    }

    pub fn peek(&mut self) -> Option<&Token> {
        match self.tokenizer.peek()? {
            State::NewLine(line, quoted) => {
                self.line = *line;
                self.quoted = *quoted;
                None
            }
            State::Token(token, line) => {
                self.line = *line;
                Some(token)
            }
        }
    }

    fn next_impl(&mut self) -> Option<Token> {
        match self.tokenizer.next()? {
            State::NewLine(line, quoted) => {
                self.line = line;
                self.quoted = quoted;
                None
            }
            State::Token(token, line) => {
                self.line = line;
                Some(token)
            }
        }
    }
}
