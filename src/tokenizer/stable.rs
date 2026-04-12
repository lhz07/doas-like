use crate::tokenizer::{QuoteState, State, Token, Tokenizer};
use std::str::Chars;

pub fn gen_tokenizer(content: &str) -> Tokenizer<impl Iterator<Item = State>> {
    let g = TokenizerInner::new(content);
    Tokenizer {
        tokenizer: g.peekable(),
        line: 1,
    }
}

pub struct TokenizerInner<'a> {
    content: Chars<'a>,
    token: Token,
    quote_state: QuoteState,
    skipping_comment: bool,
    token_empty: bool,
    line_count: usize,
    escaped: bool,
    quoted: bool,
    location: Option<Location>,
}

impl Iterator for TokenizerInner<'_> {
    type Item = State;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_impl()
    }
}

enum Location {
    TokenEmptyLineCount,
    TokenEmptySkipComment,
    LineCount,
    SkipComment,
    ReturnBrace(u8),
}

impl<'a> TokenizerInner<'a> {
    pub fn new(content: &'a str) -> Self {
        Self {
            content: content.chars(),
            token: Token::default(),
            quote_state: QuoteState::default(),
            skipping_comment: false,
            token_empty: true,
            line_count: 1,
            escaped: false,
            quoted: false,
            location: None,
        }
    }
    pub fn next_impl(&mut self) -> Option<State> {
        if let Some(location) = self.location.take() {
            match location {
                Location::TokenEmptyLineCount => {
                    if !self.token_empty {
                        self.token_empty = true;
                        self.location = Some(Location::LineCount);
                        return None;
                    }
                }
                Location::TokenEmptySkipComment => {
                    if !self.token_empty {
                        self.token_empty = true;
                        self.location = Some(Location::SkipComment);
                        return None;
                    }
                }
                Location::LineCount => self.line_count += 1,
                Location::SkipComment => self.skipping_comment = true,
                Location::ReturnBrace(ch) => {
                    self.token.str.push(ch as char);
                    return Some(State::Token(
                        self.token.finish(self.quote_state.take_option()),
                        self.line_count,
                    ));
                }
            }
        }
        for ch in &mut self.content {
            if self.skipping_comment {
                if ch != '\n' {
                    continue;
                } else {
                    // ch == '\n'
                    self.skipping_comment = false;
                }
            }
            if self.escaped {
                match ch {
                    '\n' => self.line_count += 1,
                    _ => self.token.str.push(ch),
                }
                self.escaped = false;
                continue;
            }
            if self.quoted {
                match ch {
                    '"' | '\\' => (),
                    _ => {
                        self.token.str.push(ch);
                        continue;
                    }
                }
            }
            match ch {
                '\n' => {
                    if !self.token.str.is_empty() {
                        self.token_empty = false;
                        self.location = Some(Location::TokenEmptyLineCount);
                        return Some(State::Token(
                            self.token.finish(self.quote_state.take_option()),
                            self.line_count,
                        ));
                    }
                    if !self.token_empty {
                        self.token_empty = true;
                        self.location = Some(Location::LineCount);
                        return Some(State::NewLine(self.line_count));
                    }
                    self.line_count += 1;
                }
                _ if ch.is_ascii_whitespace() => {
                    if !self.token.str.is_empty() {
                        self.token_empty = false;
                        self.location = None;
                        return Some(State::Token(
                            self.token.finish(self.quote_state.take_option()),
                            self.line_count,
                        ));
                    }
                    continue;
                }
                '{' | '}' => {
                    if !self.token.str.is_empty() {
                        self.token_empty = false;
                        self.location = Some(Location::ReturnBrace(ch as u8));
                        return Some(State::Token(
                            self.token.finish(self.quote_state.take_option()),
                            self.line_count,
                        ));
                    }
                    self.token.str.push(ch);
                    return Some(State::Token(
                        self.token.finish(self.quote_state.take_option()),
                        self.line_count,
                    ));
                }
                // skip comment
                '#' => {
                    if !self.token.str.is_empty() {
                        self.token_empty = false;
                        self.location = Some(Location::TokenEmptySkipComment);
                        return Some(State::Token(
                            self.token.finish(self.quote_state.take_option()),
                            self.line_count,
                        ));
                    }
                    if !self.token_empty {
                        self.token_empty = true;
                        self.location = Some(Location::SkipComment);
                        return Some(State::NewLine(self.line_count));
                    }
                    self.skipping_comment = true;
                }
                '\\' => {
                    self.escaped = !self.escaped;
                    continue;
                }
                '"' => {
                    self.quoted = !self.quoted;
                    match &self.quote_state {
                        QuoteState::None if self.quoted => {
                            self.quote_state = QuoteState::Half(self.token.str.len())
                        }
                        QuoteState::Half(start) if !self.quoted => {
                            if self.token.str.len() > *start {
                                self.quote_state = QuoteState::Full(*start..self.token.str.len())
                            }
                        }
                        _ => (),
                    }
                    continue;
                }
                _ => {
                    self.token.str.push(ch);
                }
            }
        }
        None
    }
}
